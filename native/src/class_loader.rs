use std::collections::HashSet;
use std::ffi::{CStr, c_void};
use std::mem::size_of;
use std::path::PathBuf;
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;

use dexsql::{DexBytes, DexInput};
use jni_sys::{
    JNI_EDETACHED, JNI_OK, JNI_VERSION_1_6, JNIEnv, JavaVM, jfieldID, jlongArray, jobject,
    jobjectArray,
};

use crate::read_string;

pub(crate) fn inputs(
    env: *mut JNIEnv,
    loader: jobject,
    is_memory_backed: bool,
) -> Result<Vec<DexInput>, String> {
    if env.is_null() || loader.is_null() {
        return Err("ClassLoader is null".into());
    }
    let _frame = LocalFrame::push(env, 16)?;
    let loader_field = field(
        env,
        c"dalvik/system/BaseDexClassLoader",
        c"pathList",
        c"Ldalvik/system/DexPathList;",
    )?;
    let elements_field = field(
        env,
        c"dalvik/system/DexPathList",
        c"dexElements",
        c"[Ldalvik/system/DexPathList$Element;",
    )?;
    let dex_file_field = field(
        env,
        c"dalvik/system/DexPathList$Element",
        c"dexFile",
        c"Ldalvik/system/DexFile;",
    )?;
    let file_name_field = field(
        env,
        c"dalvik/system/DexFile",
        c"mFileName",
        c"Ljava/lang/String;",
    )?;
    let cookie_field = if is_memory_backed {
        field(
            env,
            c"dalvik/system/DexFile",
            c"mCookie",
            c"Ljava/lang/Object;",
        )
        .ok()
    } else {
        None
    };
    let readonly = if is_memory_backed {
        readonly_mappings()
    } else {
        Vec::new()
    };
    let paths = required_object(env, loader, loader_field, "pathList")?;
    let elements = required_object(env, paths, elements_field, "dexElements")? as jobjectArray;
    let fns = unsafe { &**env };
    let count = unsafe { (fns.v1_1.GetArrayLength)(env, elements) };
    let mut result = Vec::new();
    let mut disk_paths = HashSet::new();
    let mut addresses = HashSet::new();
    let long_array_class = if cookie_field.is_some() {
        let class = unsafe { (fns.v1_1.FindClass)(env, c"[J".as_ptr()) };
        check_exception(env, "long array class")?;
        Some(class)
    } else {
        None
    };
    for index in 0..count {
        let _frame = LocalFrame::push(env, 8)?;
        let element = unsafe { (fns.v1_1.GetObjectArrayElement)(env, elements, index) };
        check_exception(env, "dexElements entry")?;
        if element.is_null() {
            continue;
        }
        let dex_file = object(env, element, dex_file_field)?;
        if dex_file.is_null() {
            continue;
        }
        let path = read_string(env, object(env, dex_file, file_name_field)?)
            .filter(|path| !path.is_empty());
        if path.as_ref().is_some_and(|path| disk_paths.contains(path)) {
            continue;
        }
        let mut memory_error = None;
        if let Some((cookie_field, long_array_class)) = cookie_field.zip(long_array_class) {
            let cookie = object(env, dex_file, cookie_field)?;
            if !cookie.is_null()
                && unsafe { (fns.v1_1.IsInstanceOf)(env, cookie, long_array_class) }
            {
                let extracted =
                    memory_images(env, cookie as jlongArray, &readonly).and_then(|images| {
                        let owner = images
                            .iter()
                            .any(|image| image.readonly && !addresses.contains(&image.address))
                            .then(|| CookieOwner::new(env, loader, dex_file))
                            .transpose()?;
                        let mut pending = HashSet::new();
                        images
                            .into_iter()
                            .enumerate()
                            .filter(|(_, image)| {
                                !addresses.contains(&image.address) && pending.insert(image.address)
                            })
                            .map(|(ordinal, image)| {
                                let bytes = image.into_bytes(owner.as_ref())?;
                                Ok((
                                    image.address,
                                    DexInput::Memory {
                                        source_name: path
                                            .clone()
                                            .unwrap_or_else(|| "in-memory".into()),
                                        entry_name: format!("cookie[{index}][{}]", ordinal + 1),
                                        bytes,
                                    },
                                ))
                            })
                            .collect::<Result<Vec<_>, String>>()
                    });
                match extracted {
                    Ok(inputs) => {
                        for (address, input) in inputs {
                            addresses.insert(address);
                            result.push(input);
                        }
                        continue;
                    }
                    Err(error) => memory_error = Some(error),
                }
            }
        }
        let path = path.ok_or_else(|| {
            format!(
                "DEX element {index} has no file path (isMemoryBacked={is_memory_backed}): {}",
                memory_error
                    .as_deref()
                    .unwrap_or("ART memory image is unavailable")
            )
        })?;
        result.retain(
            |input| !matches!(input, DexInput::Memory { source_name, .. } if source_name == &path),
        );
        disk_paths.insert(path.clone());
        result.push(DexInput::Path(PathBuf::from(path)));
    }
    if result.is_empty() {
        return Err("ClassLoader contains no DEX inputs".into());
    }
    Ok(result)
}

struct LocalFrame(*mut JNIEnv);

impl LocalFrame {
    fn push(env: *mut JNIEnv, count: i32) -> Result<Self, String> {
        let status = unsafe { ((**env).v1_2.PushLocalFrame)(env, count) };
        if status == JNI_OK {
            return Ok(Self(env));
        }
        check_exception(env, "local frame")?;
        Err("Could not allocate JNI local frame".into())
    }
}

impl Drop for LocalFrame {
    fn drop(&mut self) {
        unsafe {
            ((**self.0).v1_2.PopLocalFrame)(self.0, null_mut());
        }
    }
}

fn check_exception(env: *mut JNIEnv, operation: &str) -> Result<(), String> {
    unsafe {
        if ((**env).v1_2.ExceptionCheck)(env) {
            ((**env).v1_1.ExceptionClear)(env);
            return Err(format!("ART denied or failed JNI access to {operation}"));
        }
    }
    Ok(())
}

fn field(
    env: *mut JNIEnv,
    owner: &CStr,
    name: &CStr,
    signature: &CStr,
) -> Result<jfieldID, String> {
    unsafe {
        let fns = &**env;
        let class = (fns.v1_1.FindClass)(env, owner.as_ptr());
        check_exception(env, &owner.to_string_lossy())?;
        if class.is_null() {
            return Err(format!("Missing ART class {owner:?}"));
        }
        let id = (fns.v1_1.GetFieldID)(env, class, name.as_ptr(), signature.as_ptr());
        (fns.v1_1.DeleteLocalRef)(env, class);
        check_exception(env, &name.to_string_lossy())?;
        if id.is_null() {
            return Err(format!("Missing ART field {name:?}"));
        }
        Ok(id)
    }
}

fn object(env: *mut JNIEnv, owner: jobject, field: jfieldID) -> Result<jobject, String> {
    let value = unsafe { ((**env).v1_1.GetObjectField)(env, owner, field) };
    check_exception(env, "ClassLoader field")?;
    Ok(value)
}

fn required_object(
    env: *mut JNIEnv,
    owner: jobject,
    field: jfieldID,
    name: &str,
) -> Result<jobject, String> {
    let value = object(env, owner, field)?;
    if value.is_null() {
        return Err(format!("ART {name} is null"));
    }
    Ok(value)
}

struct CookieOwner {
    vm: *mut JavaVM,
    loader: jobject,
    dex_file: jobject,
}

unsafe impl Send for CookieOwner {}
unsafe impl Sync for CookieOwner {}

impl CookieOwner {
    fn new(env: *mut JNIEnv, loader: jobject, dex_file: jobject) -> Result<Arc<Self>, String> {
        unsafe {
            let fns = &**env;
            let mut vm = null_mut();
            if (fns.v1_2.GetJavaVM)(env, &mut vm) != JNI_OK || vm.is_null() {
                return Err("Could not retain the ART VM".into());
            }
            let loader = (fns.v1_1.NewGlobalRef)(env, loader);
            check_exception(env, "ClassLoader global reference")?;
            if loader.is_null() {
                return Err("Could not retain the ClassLoader".into());
            }
            let mut owner = Self {
                vm,
                loader,
                dex_file: null_mut(),
            };
            owner.dex_file = (fns.v1_1.NewGlobalRef)(env, dex_file);
            check_exception(env, "DexFile global reference")?;
            if owner.dex_file.is_null() {
                return Err("Could not retain the DexFile".into());
            }
            Ok(Arc::new(owner))
        }
    }
}

impl Drop for CookieOwner {
    fn drop(&mut self) {
        unsafe {
            let vm = &**self.vm;
            let mut raw_env: *mut c_void = null_mut();
            let status = (vm.v1_2.GetEnv)(self.vm, &mut raw_env, JNI_VERSION_1_6);
            let attached = status == JNI_EDETACHED;
            if attached {
                if (vm.v1_4.AttachCurrentThreadAsDaemon)(self.vm, &mut raw_env, null_mut())
                    != JNI_OK
                {
                    return;
                }
            } else if status != JNI_OK {
                return;
            }
            let env = raw_env.cast::<JNIEnv>();
            let fns = &**env;
            (fns.v1_1.DeleteGlobalRef)(env, self.dex_file);
            (fns.v1_1.DeleteGlobalRef)(env, self.loader);
            if attached {
                (vm.v1_2.DetachCurrentThread)(self.vm);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Image {
    address: usize,
    length: usize,
    readonly: bool,
}

impl Image {
    fn into_bytes(self, owner: Option<&Arc<CookieOwner>>) -> Result<DexBytes, String> {
        if self.readonly {
            let owner = owner.ok_or("ART DEX view requires a retained owner")?;
            let address = NonNull::new(self.address as *mut u8).ok_or("DEX address is null")?;
            return Ok(unsafe {
                DexBytes::from_raw_parts_with_owner(address, self.length, owner.clone())
            });
        }
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(self.length)
            .map_err(|error| error.to_string())?;
        if !read_process(self.address, snapshot.as_mut_ptr(), self.length) {
            return Err("Could not copy ART DEX image".into());
        }
        unsafe {
            snapshot.set_len(self.length);
        }
        Ok(DexBytes::from_vec(snapshot))
    }
}

fn memory_images(
    env: *mut JNIEnv,
    cookie: jlongArray,
    readonly: &[(usize, usize)],
) -> Result<Vec<Image>, String> {
    let count = unsafe { ((**env).v1_1.GetArrayLength)(env, cookie) };
    if count <= 1 {
        return Err("ART cookie contains no DEX pointers".into());
    }
    let mut pointers = vec![0; (count - 1) as usize];
    unsafe {
        ((**env).v1_1.GetLongArrayRegion)(env, cookie, 1, count - 1, pointers.as_mut_ptr());
    }
    check_exception(env, "ART DEX cookie")?;
    pointers
        .into_iter()
        .map(|pointer| inspect_image(pointer as usize, readonly))
        .collect()
}

fn inspect_image(pointer: usize, readonly: &[(usize, usize)]) -> Result<Image, String> {
    let mut layout = [0u8; size_of::<usize>() * 3];
    if !read_process(pointer, layout.as_mut_ptr(), layout.len()) {
        return Err("Unreadable ART DexFile".into());
    }
    let ptr_size = size_of::<usize>();
    let begin = usize::from_ne_bytes(layout[ptr_size..ptr_size * 2].try_into().unwrap());
    let reported_size = usize::from_ne_bytes(layout[ptr_size * 2..].try_into().unwrap());
    let mut header = [0u8; 120];
    if begin % 4 != 0
        || !read_process(begin, header.as_mut_ptr(), 112)
        || &header[..4] != b"dex\n"
        || header[7] != 0
    {
        return Err("Unreadable or unsupported ART DEX image".into());
    }
    let word =
        |offset: usize| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap()) as usize;
    let file_size = word(32);
    let header_size = word(36);
    if file_size < header_size
        || (reported_size != 0 && reported_size != file_size)
        || word(40) != 0x12345678
    {
        return Err("Invalid ART DEX header".into());
    }
    let (address, length) = if &header[4..7] == b"041" {
        if header_size != 120 || !read_process(begin, header.as_mut_ptr(), 120) {
            return Err("Unreadable DEX v41 header".into());
        }
        let length = u32::from_le_bytes(header[112..116].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(header[116..120].try_into().unwrap()) as usize;
        if offset.checked_add(file_size).is_none_or(|end| end > length) {
            return Err("Invalid ART DEX container bounds".into());
        }
        (
            begin
                .checked_sub(offset)
                .ok_or("Invalid ART DEX container base")?,
            length,
        )
    } else {
        if header_size != 112 {
            return Err("Unsupported ART DEX header size".into());
        }
        (begin, file_size)
    };
    let end = address
        .checked_add(length)
        .filter(|_| address != 0 && length <= isize::MAX as usize)
        .ok_or("ART DEX image exceeds address space")?;
    Ok(Image {
        address,
        length,
        readonly: readonly
            .iter()
            .any(|&(start, limit)| start <= address && end <= limit),
    })
}

fn readonly_mappings() -> Vec<(usize, usize)> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let range = parts.next()?;
            if !parts.next()?.starts_with("r-") {
                return None;
            }
            let (start, end) = range.split_once('-')?;
            Some((
                usize::from_str_radix(start, 16).ok()?,
                usize::from_str_radix(end, 16).ok()?,
            ))
        })
        .collect()
}

fn read_process(address: usize, destination: *mut u8, length: usize) -> bool {
    if address == 0 || address.checked_add(length).is_none() || length > isize::MAX as usize {
        return false;
    }
    let local = libc::iovec {
        iov_base: destination.cast(),
        iov_len: length,
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: length,
    };
    unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) == length as isize }
}
