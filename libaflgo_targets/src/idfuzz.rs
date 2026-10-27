pub const DOM_SIZE: usize = 256;
static mut DOM_MAP: [u8; DOM_SIZE] = [0; DOM_SIZE];

#[no_mangle]
pub unsafe extern "C" fn __idfuzz_trace_dom(id: u32) {
    if (id as usize) < DOM_SIZE {
        let p = std::ptr::addr_of_mut!(DOM_MAP).cast::<u8>().add(id as usize);
        p.write_volatile(255);
    }
}

#[no_mangle]
pub unsafe extern "C" fn __idfuzz_trace_branch(id: u32, value: u8) {
    if (id as usize) < DOM_SIZE && value != 0 {
        let p = std::ptr::addr_of_mut!(DOM_MAP).cast::<u8>().add(id as usize);
        if p.read_volatile() == 0 { p.write_volatile(value); }
    }
}

pub fn reset() {
    for i in 0..DOM_SIZE {
        unsafe { std::ptr::addr_of_mut!(DOM_MAP).cast::<u8>().add(i).write_volatile(0) }
    }
}

pub fn snapshot() -> [u8; DOM_SIZE] {
    let mut result = [0; DOM_SIZE];
    for (i, cell) in result.iter_mut().enumerate() {
        *cell = unsafe { std::ptr::addr_of!(DOM_MAP).cast::<u8>().add(i).read_volatile() };
    }
    result
}
