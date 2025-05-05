#![allow(clippy::arithmetic_side_effects)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Virtual machine for eBPF programs.

use crate::{
    ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    interpreter::Interpreter,
    memory_region::MemoryMapping,
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
};
use std::{collections::BTreeMap, fmt::Debug};

use bytemuck::Pod;
use instrument::Instrumenter;
use novafuzz_config::MM_INPUT_START;
use novafuzz_types::{
    semantic::{AccountAttribute, InputAttribute},
    SemanticMapping,
};
use std::cell::RefCell;
use std::rc::Rc;

/// NovaFuzz Instrumenter Helper
/// Convert a slice of bytes to a number
/// Order: Little Endian
/// Example:
/// ```
/// let value = [0xff, 0x00, 0x00, 0x00];
/// let num = convert_bytes_to_num::<u32>(&value);
/// assert_eq!(num, 255);
/// ```
pub fn convert_bytes_to_num<T>(value: &[u8]) -> T
where
    T: Pod + Clone,
{
    let bytes = &value[..core::mem::size_of::<T>()];
    *bytemuck::from_bytes(bytes)
}

#[cfg(not(feature = "shuttle-test"))]
use {
    rand::{thread_rng, Rng},
    std::sync::Arc,
};

#[cfg(feature = "shuttle-test")]
use shuttle::{
    rand::{thread_rng, Rng},
    sync::Arc,
};

/// Shift the RUNTIME_ENVIRONMENT_KEY by this many bits to the LSB
///
/// 3 bits for 8 Byte alignment, and 1 bit to have encoding space for the RuntimeEnvironment.
const PROGRAM_ENVIRONMENT_KEY_SHIFT: u32 = 4;
static RUNTIME_ENVIRONMENT_KEY: std::sync::OnceLock<i32> = std::sync::OnceLock::<i32>::new();

/// Returns (and if not done before generates) the encryption key for the VM pointer
pub fn get_runtime_environment_key() -> i32 {
    *RUNTIME_ENVIRONMENT_KEY
        .get_or_init(|| thread_rng().gen::<i32>() >> PROGRAM_ENVIRONMENT_KEY_SHIFT)
}

/// VM configuration settings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Maximum call depth
    pub max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    pub stack_frame_size: usize,
    /// Enables the use of MemoryMapping and MemoryRegion for address translation
    pub enable_address_translation: bool,
    /// Enables gaps in VM address space between the stack frames
    pub enable_stack_frame_gaps: bool,
    /// Maximal pc distance after which a new instruction meter validation is emitted by the JIT
    pub instruction_meter_checkpoint_distance: usize,
    /// Enable instruction meter and limiting
    pub enable_instruction_meter: bool,
    /// Enable instruction tracing
    pub enable_instruction_tracing: bool,
    /// Enable dynamic string allocation for labels
    pub enable_symbol_and_section_labels: bool,
    /// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
    pub reject_broken_elfs: bool,
    /// Ratio of native host instructions per random no-op in JIT (0 = OFF)
    pub noop_instruction_rate: u32,
    /// Enable disinfection of immediate values and offsets provided by the user in JIT
    pub sanitize_user_provided_values: bool,
    /// Avoid copying read only sections when possible
    pub optimize_rodata: bool,
    /// Use aligned memory mapping
    pub aligned_memory_mapping: bool,
    /// Allowed [SBPFVersion]s
    pub enabled_sbpf_versions: std::ops::RangeInclusive<SBPFVersion>,
}

impl Config {
    /// Returns the size of the stack memory region
    pub fn stack_size(&self) -> usize {
        self.stack_frame_size * self.max_call_depth
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_call_depth: 64,
            stack_frame_size: 4_096,
            enable_address_translation: true,
            enable_stack_frame_gaps: true,
            instruction_meter_checkpoint_distance: 10000,
            enable_instruction_meter: true,
            enable_instruction_tracing: false,
            enable_symbol_and_section_labels: false,
            reject_broken_elfs: false,
            noop_instruction_rate: 256,
            sanitize_user_provided_values: true,
            optimize_rodata: true,
            aligned_memory_mapping: true,
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3,
        }
    }
}

/// Static constructors for Executable
impl<C: ContextObject> Executable<C> {
    /// Creates an executable from an ELF file
    pub fn from_elf(elf_bytes: &[u8], loader: Arc<BuiltinProgram<C>>) -> Result<Self, EbpfError> {
        let executable = Executable::load(elf_bytes, loader)?;
        Ok(executable)
    }
    /// Creates an executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        loader: Arc<BuiltinProgram<C>>,
        sbpf_version: SBPFVersion,
        function_registry: FunctionRegistry<usize>,
    ) -> Result<Self, EbpfError> {
        Executable::new_from_text_bytes(text_bytes, loader, sbpf_version, function_registry)
            .map_err(EbpfError::ElfError)
    }
}

/// Runtime context
pub trait ContextObject {
    /// Called for every instruction executed when tracing is enabled
    fn trace(&mut self, state: [u64; 12]);
    /// Consume instructions from meter
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
}

/// Statistic of taken branches (from a recorded trace)
pub struct DynamicAnalysis {
    /// Maximal edge counter value
    pub edge_counter_max: usize,
    /// src_node, dst_node, edge_counter
    pub edges: BTreeMap<usize, BTreeMap<usize, usize>>,
}

impl DynamicAnalysis {
    /// Accumulates a trace
    pub fn new(trace_log: &[[u64; 12]], analysis: &Analysis) -> Self {
        let mut result = Self {
            edge_counter_max: 0,
            edges: BTreeMap::new(),
        };
        let mut last_basic_block = usize::MAX;
        for traced_instruction in trace_log.iter() {
            let pc = traced_instruction[11] as usize;
            if analysis.cfg_nodes.contains_key(&pc) {
                let counter = result
                    .edges
                    .entry(last_basic_block)
                    .or_default()
                    .entry(pc)
                    .or_insert(0);
                *counter += 1;
                result.edge_counter_max = result.edge_counter_max.max(*counter);
                last_basic_block = pc;
            }
        }
        result
    }
}

/// A call frame used for function calls inside the Interpreter
#[derive(Clone, Default)]
pub struct CallFrame {
    /// The caller saved registers
    pub caller_saved_registers: [u64; ebpf::SCRATCH_REGS],
    /// The callers frame pointer
    pub frame_pointer: u64,
    /// The target_pc of the exit instruction which returns back to the caller
    pub target_pc: u64,
}

/// Indices of slots inside [EbpfVm]
pub enum RuntimeEnvironmentSlot {
    /// [EbpfVm::host_stack_pointer]
    HostStackPointer = 0,
    /// [EbpfVm::call_depth]
    CallDepth = 1,
    /// [EbpfVm::context_object_pointer]
    ContextObjectPointer = 2,
    /// [EbpfVm::previous_instruction_meter]
    PreviousInstructionMeter = 3,
    /// [EbpfVm::due_insn_count]
    DueInsnCount = 4,
    /// [EbpfVm::stopwatch_numerator]
    StopwatchNumerator = 5,
    /// [EbpfVm::stopwatch_denominator]
    StopwatchDenominator = 6,
    /// [EbpfVm::registers]
    Registers = 7,
    /// [EbpfVm::program_result]
    ProgramResult = 19,
    /// [EbpfVm::memory_mapping]
    MemoryMapping = 27,
}

/// A virtual machine to run eBPF programs.
///
/// # Examples
///
/// ```
/// use solana_sbpf::{
///     aligned_memory::AlignedMemory,
///     ebpf,
///     elf::Executable,
///     memory_region::{MemoryMapping, MemoryRegion},
///     program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
///     verifier::RequisiteVerifier,
///     vm::{Config, EbpfVm},
/// };
/// use test_utils::TestContextObject;
///
/// let prog = &[
///     0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
/// let function_registry = FunctionRegistry::default();
/// let mut executable = Executable::<TestContextObject>::from_text_bytes(prog, loader.clone(), SBPFVersion::V3, function_registry).unwrap();
/// executable.verify::<RequisiteVerifier>().unwrap();
/// let mut context_object = TestContextObject::new(1);
/// let sbpf_version = executable.get_sbpf_version();
///
/// let mut stack = AlignedMemory::<{ebpf::HOST_ALIGN}>::zero_filled(executable.get_config().stack_size());
/// let stack_len = stack.len();
/// let mut heap = AlignedMemory::<{ebpf::HOST_ALIGN}>::with_capacity(0);
///
/// let regions: Vec<MemoryRegion> = vec![
///     executable.get_ro_region(),
///     MemoryRegion::new_writable(
///         stack.as_slice_mut(),
///         ebpf::MM_STACK_START,
///     ),
///     MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
///     MemoryRegion::new_writable(mem, ebpf::MM_INPUT_START),
/// ];
///
/// let memory_mapping = MemoryMapping::new(regions, executable.get_config(), sbpf_version).unwrap();
///
/// let mut vm = EbpfVm::new(loader, sbpf_version, &mut context_object, memory_mapping, stack_len);
///
/// let (instruction_count, result) = vm.execute_program(&executable, true);
/// assert_eq!(instruction_count, 1);
/// assert_eq!(result.unwrap(), 0);
/// ```
#[repr(C)]
pub struct EbpfVm<'a, C: ContextObject> {
    /// Needed to exit from the guest back into the host
    pub host_stack_pointer: *mut u64,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    pub call_depth: u64,
    /// Pointer to ContextObject
    pub context_object_pointer: &'a mut C,
    /// Last return value of instruction_meter.get_remaining()
    pub previous_instruction_meter: u64,
    /// Outstanding value to instruction_meter.consume()
    pub due_insn_count: u64,
    /// CPU cycles accumulated by the stop watch
    pub stopwatch_numerator: u64,
    /// Number of times the stop watch was used
    pub stopwatch_denominator: u64,
    /// Registers inlined
    pub registers: [u64; 12],
    /// ProgramResult inlined
    pub program_result: ProgramResult,
    /// MemoryMapping inlined
    pub memory_mapping: MemoryMapping<'a>,
    /// Stack of CallFrames used by the Interpreter
    pub call_frames: Vec<CallFrame>,
    /// Loader built-in program
    pub loader: Arc<BuiltinProgram<C>>,
    /// NovaFuzz Instrumenter
    pub instrumenter: Option<Rc<RefCell<Instrumenter>>>,
    /// TCP port for the debugger interface
    #[cfg(feature = "debugger")]
    pub debug_port: Option<u16>,
}

impl<'a, C: ContextObject> EbpfVm<'a, C> {
    /// Creates a new virtual machine instance.
    pub fn new(
        loader: Arc<BuiltinProgram<C>>,
        sbpf_version: SBPFVersion,
        context_object: &'a mut C,
        mut memory_mapping: MemoryMapping<'a>,
        stack_len: usize,
        instrumenter: Option<Rc<RefCell<Instrumenter>>>,
    ) -> Self {
        // NovaFuzz: record the depth of vm creation
        if let Some(instrumenter_rc) = &instrumenter {
            instrumenter_rc.borrow_mut().vm_depth += 1;
        }

        let config = loader.get_config();
        let mut registers = [0u64; 12];
        registers[ebpf::FRAME_PTR_REG] =
            ebpf::MM_STACK_START.saturating_add(if sbpf_version.dynamic_stack_frames() {
                // the stack is fully descending, frames start as empty and change size anytime r11 is modified
                stack_len
            } else {
                // within a frame the stack grows down, but frames are ascending
                config.stack_frame_size
            } as u64);
        if !config.enable_address_translation {
            memory_mapping = MemoryMapping::new_identity();
        }
        EbpfVm {
            host_stack_pointer: std::ptr::null_mut(),
            call_depth: 0,
            context_object_pointer: context_object,
            previous_instruction_meter: 0,
            due_insn_count: 0,
            stopwatch_numerator: 0,
            stopwatch_denominator: 0,
            registers,
            program_result: ProgramResult::Ok(0),
            memory_mapping,
            call_frames: vec![CallFrame::default(); config.max_call_depth],
            loader,
            instrumenter,
            #[cfg(feature = "debugger")]
            debug_port: None,
        }
    }

    fn extract_input_from_memory(
        &self,
        memory_mapping: &MemoryMapping,
        start_ptr: usize,
        end_ptr: usize,
    ) -> Vec<u8> {
        let mut input_bytes = Vec::new();
        for i in start_ptr..end_ptr {
            match memory_mapping.load::<u8>(i as u64) {
                ProgramResult::Ok(byte) => {
                    input_bytes.push(byte as u8);
                }
                ProgramResult::Err(e) => {
                    println!("Can't Parsing input from memory: {}", e);
                    break;
                }
            }
        }
        input_bytes
    }

    fn parse_account(
        &self,
        memory_mapping: &MemoryMapping,
        ptr: &mut usize,
        idx: u64,
        mapping: &mut SemanticMapping,
    ) {
        let mut input = self.extract_input_from_memory(
            memory_mapping,
            MM_INPUT_START as usize + *ptr,
            MM_INPUT_START as usize + *ptr + 1,
        );
        let account_duplicate = convert_bytes_to_num::<u8>(&input.clone());
        mapping.insert(
            *ptr as u64,
            InputAttribute::Account {
                index: idx,
                info: AccountAttribute::Duplicate,
            },
        );
        *ptr += 1;
        if account_duplicate != 0xff_u8 {
            // 7 bytes padding
            for i in 0..7 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::DuplicatePadding(i as u8),
                    },
                );
            }
            *ptr += 7;
        } else {
            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 1,
            );
            // let account_is_signer = convert_bytes_to_num::<u8>(&input.clone()) == 1;
            mapping.insert(
                *ptr as u64,
                InputAttribute::Account {
                    index: idx,
                    info: AccountAttribute::IsSigner,
                },
            );
            *ptr += 1;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 1,
            );
            // let account_is_writable = convert_bytes_to_num::<u8>(&input.clone()) == 1;
            mapping.insert(
                *ptr as u64,
                InputAttribute::Account {
                    index: idx,
                    info: AccountAttribute::IsWritable,
                },
            );
            *ptr += 1;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 1,
            );
            // let account_is_executable = convert_bytes_to_num::<u8>(&input.clone()) == 1;
            mapping.insert(
                *ptr as u64,
                InputAttribute::Account {
                    index: idx,
                    info: AccountAttribute::IsExecutable,
                },
            );
            *ptr += 1;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 4,
            );
            // let account_padding = convert_bytes_to_num::<[u8; 4]>(&input.clone());
            for i in 0..4 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::Padding(i as u8),
                    },
                );
            }
            *ptr += 4;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 32,
            );
            // let account_pubkey = convert_bytes_to_num::<[u8; 32]>(&input.clone());
            for i in 0..32 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::Pubkey(i as u8),
                    },
                );
            }
            *ptr += 32;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 32,
            );
            // let account_owner_pubkey = convert_bytes_to_num::<[u8; 32]>(&input.clone());
            for i in 0..32 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::OwnerPubkey(i as u8),
                    },
                );
            }
            *ptr += 32;
            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 8,
            );
            // let account_lamports = convert_bytes_to_num::<[u8; 8]>(&input.clone());
            for i in 0..8 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::Lamports(i as u8),
                    },
                );
            }
            *ptr += 8;
            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 8,
            );
            // let account_data_len = convert_bytes_to_num::<[u8; 8]>(&input.clone());
            let data_len = convert_bytes_to_num::<u64>(&input.clone());
            for i in 0..8 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::DataLen(i as u8),
                    },
                );
            }
            *ptr += 8;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + data_len as usize,
            );
            for i in 0..data_len {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::Data(i as u16),
                    },
                );
            }
            // let account_data = input.to_vec().clone();
            *ptr += data_len as usize;

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 10240,
            );
            for i in 0..10240 {
                mapping.insert(
                    *ptr as u64 + i,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::ReallocData(i as u16),
                    },
                );
            }
            // for i in 0..10240 {
            //     account.realloc_data[i] = input[i].clone();
            // }
            *ptr += 10240;

            if *ptr % 8 != 0 {
                let align_size = 8 - *ptr % 8;
                input = self.extract_input_from_memory(
                    memory_mapping,
                    MM_INPUT_START as usize + *ptr,
                    MM_INPUT_START as usize + *ptr + align_size,
                );
                // account.align_data = input.to_vec().clone();
                for i in 0..align_size {
                    mapping.insert(
                        *ptr as u64 + i as u64,
                        InputAttribute::Account {
                            index: idx,
                            info: AccountAttribute::AlignData(i as u8),
                        },
                    );
                }
                *ptr += align_size;
            }

            input = self.extract_input_from_memory(
                memory_mapping,
                MM_INPUT_START as usize + *ptr,
                MM_INPUT_START as usize + *ptr + 8,
            );
            // account.rent_epoch = convert_bytes_to_num::<[u8; 8]>(&input.clone());
            for i in 0..8 {
                mapping.insert(
                    *ptr as u64 + i as u64,
                    InputAttribute::Account {
                        index: idx,
                        info: AccountAttribute::RentEpoch(i as u8),
                    },
                );
            }
            *ptr += 8;
        }
    }

    /// Parse the input from memory
    /// Construct the input semantic mapping
    fn parse_input_from_memory(&self, memory_mapping: &MemoryMapping) -> SemanticMapping {
        let mut top_ptr: usize = 0 as usize;
        let mut mapping: SemanticMapping = SemanticMapping::default();

        let mut input = self.extract_input_from_memory(
            memory_mapping,
            MM_INPUT_START as usize + top_ptr,
            MM_INPUT_START as usize + top_ptr + 8,
        );
        let account_number = convert_bytes_to_num::<u64>(&input.clone());
        for i in 0..8 {
            mapping.insert(top_ptr as u64 + i, InputAttribute::NumberAccount);
        }
        // let mut accounts: Vec<AccountInfo> = vec![];
        top_ptr += 8;
        for idx in 0..account_number {
            self.parse_account(&memory_mapping, &mut top_ptr, idx, &mut mapping);
            // accounts.push(account);
        }

        input = self.extract_input_from_memory(
            memory_mapping,
            MM_INPUT_START as usize + top_ptr,
            MM_INPUT_START as usize + top_ptr + 8,
        );
        let instruction_number = convert_bytes_to_num::<u64>(&input.clone());
        for i in 0..8 {
            mapping.insert(top_ptr as u64 + i, InputAttribute::NumberInstruction);
        }
        top_ptr += 8;
        // TODO: check if this is correct
        // let mut input_converted = Input::new(account_number, instruction_number);
        // input_converted.accounts = accounts.clone();

        input = self.extract_input_from_memory(
            memory_mapping,
            MM_INPUT_START as usize + top_ptr,
            MM_INPUT_START as usize + top_ptr + instruction_number as usize,
        );
        // input_converted.instructions = input.clone();
        for i in 0..instruction_number as u64 {
            mapping.insert(
                top_ptr as u64 + i,
                InputAttribute::Instruction { index: i as u64 },
            );
        }
        top_ptr += instruction_number as usize;

        input = self.extract_input_from_memory(
            memory_mapping,
            MM_INPUT_START as usize + top_ptr,
            MM_INPUT_START as usize + top_ptr + 32,
        );
        // input_converted.program_id = convert_bytes_to_num::<[u8; 32]>(&input.clone());
        for i in 0..32 {
            mapping.insert(
                top_ptr as u64 + i,
                InputAttribute::ProgramId { index: i as u8 },
            );
        }
        top_ptr += 32;
        mapping
    }

    /// Execute the program
    ///
    /// If interpreted = `false` then the JIT compiled executable is used.
    pub fn execute_program(
        &mut self,
        executable: &Executable<C>,
        interpreted: bool,
    ) -> (u64, ProgramResult) {
        debug_assert!(Arc::ptr_eq(&self.loader, executable.get_loader()));
        self.registers[1] = ebpf::MM_INPUT_START;
        self.registers[11] = executable.get_entrypoint_instruction_offset() as u64;
        let config = executable.get_config();
        let initial_insn_count = self.context_object_pointer.get_remaining();
        self.previous_instruction_meter = initial_insn_count;
        self.due_insn_count = 0;
        self.program_result = ProgramResult::Ok(0);
        if true || interpreted {
            // NovaFuzzer, set to true to always interpret
            println!("NovaFuzzer: interpret: {:?}", self.instrumenter);
            let semantic_input_option = if self.instrumenter.is_some() {
                // Takes immutable borrow of self, which is okay here
                Some(self.parse_input_from_memory(&self.memory_mapping))
            } else {
                None
            };

            // If input was parsed, update the instrumenter
            if let Some(semantic_input) = semantic_input_option {
                // Now, get the mutable borrow again, only when needed.
                // This borrow is short-lived.
                if let Some(instrumenter_rc) = &self.instrumenter {
                    // instrumenter_mut is &mut Instrumenter here
                    let mut instrumenter_mut = instrumenter_rc.borrow_mut();
                    instrumenter_mut.semantic_input = semantic_input;
                    // instrumenter_mut.taint_engine.activate(semantic_input);
                }
                // Mutable borrow of self.instrumenter ends here
            }

            #[cfg(feature = "debugger")]
            let debug_port = self.debug_port.clone();
            let mut interpreter = Interpreter::new(self, executable, self.registers);
            #[cfg(feature = "debugger")]
            if let Some(debug_port) = debug_port {
                crate::debugger::execute(&mut interpreter, debug_port);
            } else {
                while interpreter.step() {}
            }
            #[cfg(not(feature = "debugger"))]
            while interpreter.step() {}
        } else {
            #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            {
                let compiled_program = match executable
                    .get_compiled_program()
                    .ok_or_else(|| EbpfError::JitNotCompiled)
                {
                    Ok(compiled_program) => compiled_program,
                    Err(error) => return (0, ProgramResult::Err(error)),
                };
                compiled_program.invoke(config, self, self.registers);
            }
            #[cfg(not(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64")))]
            {
                return (0, ProgramResult::Err(EbpfError::JitNotCompiled));
            }
        };
        let instruction_count = if config.enable_instruction_meter {
            self.context_object_pointer.consume(self.due_insn_count);
            initial_insn_count.saturating_sub(self.context_object_pointer.get_remaining())
        } else {
            0
        };
        let mut result = ProgramResult::Ok(0);
        std::mem::swap(&mut result, &mut self.program_result);
        (instruction_count, result)
    }

    /// Invokes a built-in function
    pub fn invoke_function(&mut self, function: BuiltinFunction<C>) {
        function(
            unsafe {
                std::ptr::addr_of_mut!(*self)
                    .cast::<u64>()
                    .offset(get_runtime_environment_key() as isize)
                    .cast::<Self>()
            },
            self.registers[1],
            self.registers[2],
            self.registers[3],
            self.registers[4],
            self.registers[5],
        );
    }
}
