# Chapter 47: Deployment Diagram

```mermaid
node "Local Host Machine" {
    node "FastAPI Server" {
        artifact "MSA API Core"
    }
    node "Ollama Daemon" {
        artifact "Qwen-3.5 4B Model"
    }
    node "Android Emulator" {
        artifact "Android VM Image"
    }
}
```
