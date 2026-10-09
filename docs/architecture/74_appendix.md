# Chapter 74: Appendix

### Sample Frida Hooking Script (`frida_engine.py`)
```javascript
Java.perform(function() {
    // Hook SharedPreferences writes
    var editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    editor.putString.implementation = function(key, value) {
        send({
            type: "storage",
            api: "SharedPreferences.Editor.putString",
            key: key,
            value: value
        });
        return this.putString(key, value);
    };
});
```
