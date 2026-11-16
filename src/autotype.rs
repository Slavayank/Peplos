//! Windows auto-type for the last window active before Peplos.

use std::{
    sync::atomic::{AtomicBool, AtomicIsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::HWND,
    UI::{
        Input::KeyboardAndMouse::{
            GetAsyncKeyState, GetKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
            KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VK_CONTROL, VK_LWIN, VK_MENU, VK_RETURN, VK_RWIN,
            VK_SHIFT, VK_TAB,
        },
        WindowsAndMessaging::{
            GetClassNameW, GetForegroundWindow, GetWindow, GetWindowLongPtrW,
            GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, GWL_EXSTYLE,
            GW_HWNDNEXT, WM_KEYDOWN, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
        },
    },
};
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
use zeroize::Zeroizing;

static PREVIOUS_WINDOW: AtomicIsize = AtomicIsize::new(0);
static CTRL_V_PRESSED: AtomicBool = AtomicBool::new(false);

pub fn window_handle(window: &winit::window::Window) -> Option<isize> {
    let handle = window.window_handle().ok()?;
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return None;
    };
    Some(handle.hwnd.get())
}

pub fn remember_previous_window(own: HWND, other: isize) {
    let target = other as HWND;
    if valid_target(own, target) && !system_window(target) {
        PREVIOUS_WINDOW.store(other, Ordering::Release);
    }
}

pub fn observe_key_message(message: u32, wparam: usize, lparam: isize) {
    // egui-winit turns Ctrl+V into Paste, and emits nothing if the clipboard is empty.
    // Remember the native key press so auto-type works regardless of clipboard contents.
    if message != WM_KEYDOWN || wparam != b'V' as usize || (lparam & (1 << 30)) != 0 {
        return;
    }
    let control_down = unsafe { GetKeyState(VK_CONTROL as i32) } < 0;
    let alt_down = unsafe { GetKeyState(VK_MENU as i32) } < 0;
    if control_down && !alt_down {
        CTRL_V_PRESSED.store(true, Ordering::Release);
    }
}

pub fn take_hotkey() -> bool {
    CTRL_V_PRESSED.swap(false, Ordering::AcqRel)
}

pub fn target_window(own: isize) -> Option<isize> {
    let own_hwnd = own as HWND;
    if !same_process_window(own_hwnd, unsafe { GetForegroundWindow() }) {
        return None;
    }
    // WM_ACTIVATE may provide a null previous HWND. The next suitable window in
    // Z-order is the one Windows will normally activate when Peplos minimizes.
    window_behind(own_hwnd)
        .or_else(|| {
            let previous = PREVIOUS_WINDOW.load(Ordering::Acquire) as HWND;
            if valid_target(own_hwnd, previous) && !system_window(previous) {
                Some(previous)
            } else {
                None
            }
        })
        .map(|window| window as isize)
}

fn same_process_window(first: HWND, second: HWND) -> bool {
    if first.is_null() || second.is_null() {
        return false;
    }
    let mut first_process = 0;
    let mut second_process = 0;
    unsafe {
        GetWindowThreadProcessId(first, &mut first_process);
        GetWindowThreadProcessId(second, &mut second_process);
    }
    first_process != 0 && first_process == second_process
}

fn window_behind(own: HWND) -> Option<HWND> {
    let mut window = unsafe { GetWindow(own, GW_HWNDNEXT) };
    for _ in 0..64 {
        if window.is_null() || window == own {
            return None;
        }
        if valid_target(own, window) && !system_window(window) {
            return Some(window);
        }
        let next = unsafe { GetWindow(window, GW_HWNDNEXT) };
        if next == window {
            return None;
        }
        window = next;
    }
    None
}

fn valid_target(own: HWND, target: HWND) -> bool {
    valid_external_window(own, target)
        && unsafe { IsIconic(target) } == 0
        && unsafe { GetWindowLongPtrW(target, GWL_EXSTYLE) } as u32
            & (WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE)
            == 0
}

fn system_window(window: HWND) -> bool {
    let mut class = [0u16; 128];
    let length = unsafe { GetClassNameW(window, class.as_mut_ptr(), class.len() as i32) };
    if length <= 0 {
        return false;
    }
    let name = String::from_utf16_lossy(&class[..length as usize]);
    matches!(name.as_str(), "Progman" | "WorkerW" | "Shell_TrayWnd")
}

fn valid_external_window(own: HWND, target: HWND) -> bool {
    if target.is_null()
        || target == own
        || unsafe { IsWindow(target) } == 0
        || unsafe { IsWindowVisible(target) } == 0
    {
        return false;
    }
    let mut own_process = 0;
    let mut target_process = 0;
    unsafe {
        GetWindowThreadProcessId(own, &mut own_process);
        GetWindowThreadProcessId(target, &mut target_process);
    }
    own_process != 0 && target_process != 0 && own_process != target_process
}

pub fn run(
    own: isize,
    target: isize,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<(), String> {
    let own_hwnd = own as HWND;
    let target_hwnd = target as HWND;
    let deadline = Instant::now() + Duration::from_secs(3);

    while unsafe { IsIconic(own_hwnd) } == 0 {
        if Instant::now() >= deadline {
            return Err("Не удалось свернуть окно Peplos".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !valid_target(own_hwnd, target_hwnd) || system_window(target_hwnd) {
        return Err("Предыдущее окно больше недоступно".into());
    }

    while unsafe { GetForegroundWindow() } != target_hwnd || modifiers_pressed() {
        if !valid_target(own_hwnd, target_hwnd) {
            return Err("Предыдущее окно больше недоступно".into());
        }
        if Instant::now() >= deadline {
            return Err("Windows не активировала ожидаемое окно".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut events = input_sequence(&username, &password);
    // Do not send a password to another window if focus changed during preparation.
    if unsafe { GetForegroundWindow() } != target_hwnd {
        wipe_inputs(&mut events);
        return Err("Фокус изменился; быстрый ввод отменён".into());
    }
    let sent = unsafe {
        SendInput(
            events.len() as u32,
            events.as_ptr(),
            size_of::<INPUT>() as i32,
        )
    };
    let expected = events.len() as u32;
    wipe_inputs(&mut events);
    if sent != expected {
        return Err("Windows не приняла быстрый ввод; проверьте права целевого приложения".into());
    }
    Ok(())
}

fn modifiers_pressed() -> bool {
    [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN, b'V' as u16]
        .into_iter()
        .any(|key| unsafe { GetAsyncKeyState(key as i32) } < 0)
}

fn input_sequence(username: &str, password: &str) -> Vec<INPUT> {
    let mut events = Vec::with_capacity((username.len() + password.len()) * 2 + 4);
    for unit in username.encode_utf16() {
        events.push(key_input(0, unit, KEYEVENTF_UNICODE));
        events.push(key_input(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
    }
    events.push(key_input(VK_TAB, 0, 0));
    events.push(key_input(VK_TAB, 0, KEYEVENTF_KEYUP));
    for unit in password.encode_utf16() {
        events.push(key_input(0, unit, KEYEVENTF_UNICODE));
        events.push(key_input(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
    }
    events.push(key_input(VK_RETURN, 0, 0));
    events.push(key_input(VK_RETURN, 0, KEYEVENTF_KEYUP));
    events
}

fn key_input(key: u16, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn wipe_inputs(events: &mut [INPUT]) {
    for event in events {
        unsafe { std::ptr::write_volatile(event, INPUT::default()) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_login_then_tab_password_and_enter() {
        let mut events = input_sequence("ю🌐", "päss");
        let keys: Vec<(u16, u16, u32)> = events
            .iter()
            .map(|event| {
                let key = unsafe { event.Anonymous.ki };
                (key.wVk, key.wScan, key.dwFlags)
            })
            .collect();
        assert_eq!(keys.len(), 18);
        assert_eq!(keys[0], (0, 'ю' as u16, KEYEVENTF_UNICODE));
        assert_eq!(keys[6], (VK_TAB, 0, 0));
        assert_eq!(keys[7], (VK_TAB, 0, KEYEVENTF_KEYUP));
        assert_eq!(keys[16], (VK_RETURN, 0, 0));
        assert_eq!(keys[17], (VK_RETURN, 0, KEYEVENTF_KEYUP));
        wipe_inputs(&mut events);
    }
}
