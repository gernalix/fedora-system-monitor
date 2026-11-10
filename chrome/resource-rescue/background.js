/* Event-driven tab-title snapshots only. No polling, storage, URLs or tab PID guesses. */
import {tabTitleSnapshot} from './model.js';

let pending;
function scheduleSnapshot() {
  clearTimeout(pending);
  pending=setTimeout(async () => {
    try {
      const tabs=await chrome.tabs.query({});
      await chrome.runtime.sendNativeMessage(
        'com.gernalix.fsm_resource_rescue',
        tabTitleSnapshot(tabs,crypto.randomUUID())
      );
    } catch (_) {
      // Missing native host is an allowed degraded mode. Never log tab titles.
    }
  },1000);
}
chrome.runtime.onStartup.addListener(scheduleSnapshot);
chrome.runtime.onInstalled.addListener(scheduleSnapshot);
chrome.tabs.onCreated.addListener(scheduleSnapshot);
chrome.tabs.onUpdated.addListener(scheduleSnapshot);
chrome.tabs.onRemoved.addListener(scheduleSnapshot);
chrome.tabs.onActivated.addListener(scheduleSnapshot);
chrome.tabs.onReplaced.addListener(scheduleSnapshot);
chrome.tabs.onAttached.addListener(scheduleSnapshot);
chrome.tabs.onDetached.addListener(scheduleSnapshot);

// Also prime the snapshot when the extension is reloaded.
scheduleSnapshot();
