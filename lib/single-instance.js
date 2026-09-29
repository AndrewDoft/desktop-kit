"use strict";
// One app per profile. Returns true when this process holds the lock; otherwise
// quits and returns false. `onSecond` runs in the first instance when a second
// launch is attempted (surface the window there).
function singleInstance(app, onSecond) {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return false;
  }
  app.on("second-instance", (...args) => onSecond && onSecond(...args));
  return true;
}

module.exports = { singleInstance };
