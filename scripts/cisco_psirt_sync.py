from extras.scripts import Script
from netbox_cisco_psirt.utilities import sync_cisco_psirt_data

class CiscoPsirtSyncScript(Script):
    class Meta:
        name = "Cisco PSIRT Synchronization"
        description = "Fetches Cisco PSIRT advisories and updates device vulnerabilities based on OS versions."
        commit_default = True

    def run(self, data, commit):
        script_instance = self
        
        # A simple wrapper to redirect stdout-like writes to the script logger
        class ScriptLogger:
            def write(self, msg):
                # Clean up newlines
                msg = msg.strip()
                if msg:
                    script_instance.log_info(msg)
                    
        script_instance.log_info("Starting Cisco PSIRT sync via Custom Script...")
        
        try:
            sync_cisco_psirt_data(ScriptLogger())
            script_instance.log_success("Cisco PSIRT Sync completed successfully.")
            return "Finished."
        except Exception as e:
            script_instance.log_failure(f"Sync failed: {e}")
            raise
