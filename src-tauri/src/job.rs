#[cfg(windows)]
mod platform {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};
    pub struct ProcessJob { handle: HANDLE }
    unsafe impl Send for ProcessJob {}
    unsafe impl Sync for ProcessJob {}
    impl ProcessJob {
        pub fn new() -> Result<Self,String> { unsafe { let h=CreateJobObjectW(std::ptr::null(),std::ptr::null()); if h.is_null(){return Err(std::io::Error::last_os_error().to_string())} let mut i:JOBOBJECT_EXTENDED_LIMIT_INFORMATION=zeroed(); i.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; if SetInformationJobObject(h,JobObjectExtendedLimitInformation,&i as *const _ as *const _,size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)==0{CloseHandle(h);return Err(std::io::Error::last_os_error().to_string())} Ok(Self{handle:h}) } }
        pub fn assign_pid(&self,pid:u32)->Result<(),String>{unsafe{let p=OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE,0,pid);if p.is_null(){return Err(std::io::Error::last_os_error().to_string())}let ok=AssignProcessToJobObject(self.handle,p);CloseHandle(p);if ok==0{return Err(std::io::Error::last_os_error().to_string())}Ok(())}}
    }
    impl Drop for ProcessJob{fn drop(&mut self){unsafe{CloseHandle(self.handle);}}}
}
#[cfg(not(windows))] mod platform { pub struct ProcessJob; impl ProcessJob { pub fn new()->Result<Self,String>{Ok(Self)} pub fn assign_pid(&self,_:u32)->Result<(),String>{Ok(())} } }
pub use platform::ProcessJob;
