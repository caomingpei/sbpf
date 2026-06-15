#![allow(clippy::literal_string_with_formatting_args)]

use solana_sbpf::{
    assembler::assemble,
    ebpf,
    elf::Executable,
    error::ProgramResult,
    memory_region::MemoryRegion,
    program::BuiltinProgram,
    verifier::RequisiteVerifier,
    vm::{Config, RuntimeEnvironmentSlot},
};
use std::{fs::File, io::Read, sync::Arc};
use test_utils::{create_vm, syscalls, TestContextObject};

#[test]
fn test_runtime_environment_slots() {
    let mut file = File::open("tests/elfs/relative_call_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    let mut context_object = TestContextObject::default();
    create_vm!(
        env,
        &executable,
        &mut context_object,
        stack,
        heap,
        Vec::new(),
        None
    );

    macro_rules! check_slot {
        ($env:expr, $entry:ident, $slot:ident) => {
            assert_eq!(
                unsafe {
                    std::ptr::addr_of!($env.$entry)
                        .cast::<u64>()
                        .offset_from(std::ptr::addr_of!($env).cast::<u64>()) as usize
                },
                RuntimeEnvironmentSlot::$slot as usize,
            );
        };
    }

    check_slot!(env, host_stack_pointer, HostStackPointer);
    check_slot!(env, call_depth, CallDepth);
    check_slot!(env, context_object_pointer, ContextObjectPointer);
    check_slot!(env, previous_instruction_meter, PreviousInstructionMeter);
    check_slot!(env, due_insn_count, DueInsnCount);
    check_slot!(env, stopwatch_numerator, StopwatchNumerator);
    check_slot!(env, stopwatch_denominator, StopwatchDenominator);
    check_slot!(env, registers, Registers);
    check_slot!(env, program_result, ProgramResult);
    check_slot!(env, memory_mapping, MemoryMapping);
}

#[test]
fn test_builtin_program_eq() {
    let mut builtin_program_a = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_b = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_c = BuiltinProgram::new_loader(Config::default());
    builtin_program_a
        .register_function("log", syscalls::SyscallString::vm)
        .unwrap();
    builtin_program_a
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    builtin_program_b
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    builtin_program_b
        .register_function("log", syscalls::SyscallString::vm)
        .unwrap();
    builtin_program_c
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    assert_eq!(builtin_program_a, builtin_program_b);
    assert_ne!(builtin_program_a, builtin_program_c);
}

#[test]
fn overflow_lamports_candidate_from_interpreter_store() {
    let loader = Arc::new(BuiltinProgram::new_loader(Config {
        enable_instruction_tracing: true,
        ..Config::default()
    }));
    let executable = assemble(
        "
        add64 r10, 0
        mov64 r2, -1
        add64 r2, 2
        stxdw [r1+80], r2
        exit
        ",
        loader,
    )
    .expect("assemble overflow lamports probe");
    executable
        .verify::<RequisiteVerifier>()
        .expect("verify overflow lamports probe");

    let mut input = single_account_serialized_input();
    let mem_region = MemoryRegion::new_writable(&mut input, ebpf::MM_INPUT_START);
    let mut context_object = TestContextObject::new(8);
    create_vm!(
        vm,
        &executable,
        &mut context_object,
        stack,
        heap,
        vec![mem_region],
        None
    );

    let (_, result) = vm.execute_program(&executable, true);
    assert!(matches!(result, ProgramResult::Ok(0)));

    let snapshot = vm.instrumenter.borrow().snapshot();
    assert_eq!(snapshot.overflow_lamports_writes.len(), 1);

    let write = &snapshot.overflow_lamports_writes[0];
    assert_eq!(write.account_index, 0);
    assert_eq!(write.range_start, 0);
    assert_eq!(write.range_end, 7);
    assert_eq!(write.value, 1);
    assert_eq!(write.size, 8);
}

fn single_account_serialized_input() -> Vec<u8> {
    const INPUT_LEN: usize = 8 + 88 + 10240 + 8 + 8 + 32;

    let mut input = vec![0u8; INPUT_LEN];
    write_u64(&mut input, 0, 1);
    input[8] = 0xff;
    write_u64(&mut input, 88, 0);
    write_u64(&mut input, 10344, 0);
    input
}

fn write_u64(input: &mut [u8], offset: usize, value: u64) {
    input[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
