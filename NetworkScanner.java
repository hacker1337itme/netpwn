import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class NetworkScanner {
    
    // Scanner configuration
    private static final int TIMEOUT = 3000; // 3 seconds timeout
    private static final int THREAD_POOL_SIZE = 100;
    private static final int MAX_PORT = 65535;
    private static final List<Integer> COMMON_PORTS = Arrays.asList(
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    );
    
    private final ExecutorService executorService;
    private final List<ScanResult> scanResults;
    private final Set<String> activeHosts;
    private int totalTasks = 0;
    private int completedTasks = 0;
    
    // Service patterns (reused from your ServiceIdentifier)
    private static final Map<String, ServiceInfo> SERVICE_PATTERNS = new LinkedHashMap<>();
    
    static {
        initializeServicePatterns();
    }
    
    private static class ServiceInfo {
        String name;
        String category;
        int priority;
        
        ServiceInfo(String name, String category, int priority) {
            this.name = name;
            this.category = category;
            this.priority = priority;
        }
    }
    
    private static void initializeServicePatterns() {
        // Web Servers
        addPattern("apache", new ServiceInfo("Apache HTTP Server", "Web Server", 10));
        addPattern("nginx", new ServiceInfo("Nginx", "Web Server", 10));
        addPattern("iis", new ServiceInfo("Microsoft IIS", "Web Server", 10));
        addPattern("tomcat", new ServiceInfo("Apache Tomcat", "Application Server", 10));
        addPattern("jetty", new ServiceInfo("Eclipse Jetty", "Application Server", 10));
        
        // SSH
        addPattern("ssh", new ServiceInfo("SSH", "Remote Access", 10));
        addPattern("openssh", new ServiceInfo("OpenSSH", "Remote Access", 10));
        
        // FTP
        addPattern("ftp", new ServiceInfo("FTP", "File Transfer", 10));
        addPattern("vsftpd", new ServiceInfo("vsFTPd", "File Transfer", 10));
        
        // Databases
        addPattern("mysql", new ServiceInfo("MySQL", "Database", 10));
        addPattern("postgresql", new ServiceInfo("PostgreSQL", "Database", 10));
        addPattern("mongodb", new ServiceInfo("MongoDB", "NoSQL Database", 10));
        addPattern("redis", new ServiceInfo("Redis", "In-Memory Database", 10));
        
        // Mail
        addPattern("smtp", new ServiceInfo("SMTP", "Email", 9));
        addPattern("pop3", new ServiceInfo("POP3", "Email", 9));
        addPattern("imap", new ServiceInfo("IMAP", "Email", 9));
        
        // Remote Access
        addPattern("rdp", new ServiceInfo("RDP", "Remote Access", 9));
        addPattern("vnc", new ServiceInfo("VNC", "Remote Access", 9));
        addPattern("telnet", new ServiceInfo("Telnet", "Remote Access", 9));
        
        // File Sharing
        addPattern("smb", new ServiceInfo("SMB/CIFS", "File Sharing", 8));
        addPattern("nfs", new ServiceInfo("NFS", "File Sharing", 8));
        
        // Network Services
        addPattern("dns", new ServiceInfo("DNS", "Network Service", 7));
        addPattern("snmp", new ServiceInfo("SNMP", "Network Management", 7));
        
        // Messaging
        addPattern("irc", new ServiceInfo("IRC", "Chat", 7));
        addPattern("mqtt", new ServiceInfo("MQTT", "IoT Messaging", 7));
        
        // Version Control
        addPattern("git", new ServiceInfo("Git", "Version Control", 8));
        addPattern("svn", new ServiceInfo("Subversion", "Version Control", 8));
        
        // Container
        addPattern("docker", new ServiceInfo("Docker", "Container", 9));
        
        // Development
        addPattern("jenkins", new ServiceInfo("Jenkins", "CI/CD", 8));
        addPattern("gitlab", new ServiceInfo("GitLab", "DevOps Platform", 8));
        
        // Generic
        addPattern("http", new ServiceInfo("HTTP", "Web", 1));
        addPattern("https", new ServiceInfo("HTTPS", "Web", 1));
    }
    
    private static void addPattern(String pattern, ServiceInfo info) {
        SERVICE_PATTERNS.put(pattern.toLowerCase(), info);
    }
    
    public NetworkScanner() {
        this.executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        this.scanResults = new CopyOnWriteArrayList<>();
        this.activeHosts = ConcurrentHashMap.newKeySet();
    }
    
    /**
     * Scan a CIDR network range
     */
    public void scanCIDR(String cidr) throws UnknownHostException {
        scanCIDR(cidr, COMMON_PORTS);
    }
    
    /**
     * Scan a CIDR network range with custom ports
     */
    public void scanCIDR(String cidr, List<Integer> ports) throws UnknownHostException {
        String[] parts = cidr.split("/");
        String networkAddress = parts[0];
        int prefixLength = Integer.parseInt(parts[1]);
        
        InetAddress startAddress = InetAddress.getByName(networkAddress);
        int startIP = ipToInt(startAddress);
        
        // Calculate number of hosts
        long numberOfHosts = (long) Math.pow(2, 32 - prefixLength);
        
        System.out.println("Starting scan of " + cidr + " (" + numberOfHosts + " hosts)");
        System.out.println("Scanning " + ports.size() + " ports per host");
        System.out.println("Thread pool size: " + THREAD_POOL_SIZE);
        System.out.println("=".repeat(80));
        
        long startTime = System.currentTimeMillis();
        
        // Calculate tasks
        totalTasks = (int) Math.min(numberOfHosts, 65536) * ports.size();
        
        // Scan each IP in the range
        for (long i = 1; i <= numberOfHosts; i++) {
            int currentIP = startIP + (int) i;
            if (currentIP == ipToInt(startAddress)) continue; // Skip network address
            
            String hostAddress = intToIp(currentIP);
            if (isValidHost(hostAddress)) {
                scanHost(hostAddress, ports);
            }
        }
        
        waitForCompletion();
        
        long endTime = System.currentTimeMillis();
        System.out.println("\n" + "=".repeat(80));
        System.out.println("Scan completed in " + (endTime - startTime) / 1000 + " seconds");
        System.out.println("Active hosts found: " + activeHosts.size());
        System.out.println("Open ports discovered: " + scanResults.size());
    }
    
    /**
     * Scan a single host on common ports
     */
    public void scanHost(String host) {
        scanHost(host, COMMON_PORTS);
    }
    
    /**
     * Scan a single host on specified ports
     */
    public void scanHost(String host, List<Integer> ports) {
        for (int port : ports) {
            submitScanTask(host, port);
        }
    }
    
    private void submitScanTask(String host, int port) {
        executorService.submit(() -> {
            try {
                ScanResult result = scanPort(host, port);
                if (result != null) {
                    scanResults.add(result);
                    activeHosts.add(host);
                    
                    // Print real-time results
                    synchronized (System.out) {
                        System.out.printf("[%s] %s:%d - %s (Version: %s)%n",
                            LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                            host, port, result.serviceName,
                            result.version != null ? result.version : "Unknown");
                    }
                }
                
                // Update progress
                completedTasks++;
                if (completedTasks % 100 == 0) {
                    printProgress();
                }
            } catch (Exception e) {
                // Ignore connection errors
            }
        });
    }
    
    private ScanResult scanPort(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            
            // Try to read banner
            String banner = readBanner(socket);
            
            // Identify service
            ServiceMatch serviceMatch = identifyServiceByBanner(banner);
            
            return new ScanResult(host, port, serviceMatch.name, 
                                 serviceMatch.category, serviceMatch.version, 
                                 banner, LocalDateTime.now());
            
        } catch (SocketTimeoutException e) {
            return null;
        } catch (IOException e) {
            return null;
        }
    }
    
    private String readBanner(Socket socket) {
        StringBuilder banner = new StringBuilder();
        
        try {
            socket.setSoTimeout(TIMEOUT);
            
            // Set up input stream with buffered reader
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream()), 8192
            );
            
            // Read initial banner (wait a bit for response)
            socket.setSoTimeout(1000);
            
            // Read available data
            int readCount = 0;
            while (reader.ready() && readCount < 10) {
                String line = reader.readLine();
                if (line != null) {
                    banner.append(line).append("\n");
                }
                readCount++;
            }
            
            // If no banner received, try to send a generic probe
            if (banner.length() == 0) {
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println("HEAD / HTTP/1.0\r\n\r\n");
                
                // Wait for response
                Thread.sleep(100);
                
                while (reader.ready() && readCount < 10) {
                    String line = reader.readLine();
                    if (line != null) {
                        banner.append(line).append("\n");
                    }
                    readCount++;
                }
            }
            
        } catch (Exception e) {
            // Ignore read errors
        }
        
        return banner.length() > 0 ? banner.toString() : null;
    }
    
    /**
     * Service identification (simplified from your ServiceIdentifier)
     */
    private ServiceMatch identifyServiceByBanner(String banner) {
        if (banner == null || banner.trim().isEmpty()) {
            return new ServiceMatch("Unknown", "Unknown", null);
        }
        
        String bannerLower = banner.toLowerCase();
        ServiceMatch bestMatch = new ServiceMatch("Unknown", "Unknown", null);
        
        for (Map.Entry<String, ServiceInfo> entry : SERVICE_PATTERNS.entrySet()) {
            String pattern = entry.getKey();
            ServiceInfo info = entry.getValue();
            
            Pattern compiledPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            Matcher matcher = compiledPattern.matcher(bannerLower);
            
            if (matcher.find()) {
                String version = extractVersion(banner);
                return new ServiceMatch(info.name, info.category, version);
            }
        }
        
        return bestMatch;
    }
    
    private String extractVersion(String banner) {
        Pattern versionPattern = Pattern.compile("(\\d+\\.\\d+\\.\\d+|\\d+\\.\\d+)");
        Matcher matcher = versionPattern.matcher(banner);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    private boolean isValidHost(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return !address.isLoopbackAddress() && !address.isLinkLocalAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
    
    private void printProgress() {
        int percentage = (int) ((completedTasks * 100.0) / totalTasks);
        System.out.printf("Progress: %d/%d tasks completed (%d%%)%n", 
                         completedTasks, totalTasks, percentage);
    }
    
    private void waitForCompletion() {
        executorService.shutdown();
        try {
            executorService.awaitTermination(1, TimeUnit.HOURS);
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
    
    // Helper methods for IP conversion
    private static int ipToInt(InetAddress ip) {
        byte[] octets = ip.getAddress();
        int result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }
    
    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }
    
    /**
     * Scan Result Class
     */
    public static class ScanResult {
        public String host;
        public int port;
        public String serviceName;
        public String category;
        public String version;
        public String banner;
        public LocalDateTime timestamp;
        
        public ScanResult(String host, int port, String serviceName, 
                         String category, String version, String banner, 
                         LocalDateTime timestamp) {
            this.host = host;
            this.port = port;
            this.serviceName = serviceName;
            this.category = category;
            this.version = version;
            this.banner = banner;
            this.timestamp = timestamp;
        }
        
        @Override
        public String toString() {
            return String.format("%s:%d - %s [%s] %s", 
                host, port, serviceName, category, 
                version != null ? version : "");
        }
    }
    
    public static class ServiceMatch {
        public String name;
        public String category;
        public String version;
        
        public ServiceMatch(String name, String category, String version) {
            this.name = name;
            this.category = category;
            this.version = version;
        }
    }
    
    /**
     * Export results to CSV
     */
    public void exportToCSV(String filename) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Host,Port,Service,Category,Version,Banner,Timestamp");
            for (ScanResult result : scanResults) {
                writer.printf("\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    result.host, result.port, result.serviceName, result.category,
                    result.version != null ? result.version : "",
                    result.banner != null ? result.banner.replace("\"", "\"\"") : "",
                    result.timestamp);
            }
        }
        System.out.println("Results exported to " + filename);
    }
    
    /**
     * Get scan statistics
     */
    public void printStatistics() {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("SCAN STATISTICS");
        System.out.println("=".repeat(80));
        System.out.printf("Total active hosts: %d%n", activeHosts.size());
        System.out.printf("Total open ports: %d%n", scanResults.size());
        
        // Group by service
        Map<String, Integer> serviceCount = new HashMap<>();
        for (ScanResult result : scanResults) {
            serviceCount.merge(result.serviceName, 1, Integer::sum);
        }
        
        System.out.println("\nTop Services:");
        serviceCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> System.out.printf("  %s: %d occurrences%n", 
                entry.getKey(), entry.getValue()));
        
        // Group by category
        Map<String, Integer> categoryCount = new HashMap<>();
        for (ScanResult result : scanResults) {
            categoryCount.merge(result.category, 1, Integer::sum);
        }
        
        System.out.println("\nService Categories:");
        categoryCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .forEach(entry -> System.out.printf("  %s: %d%n", 
                entry.getKey(), entry.getValue()));
    }
    
    /**
     * Main method
     */
    public static void main(String[] args) {
        NetworkScanner scanner = new NetworkScanner();
        
        // Parse command line arguments
        String cidr = "192.168.1.0/24"; // Default local network
        List<Integer> ports = COMMON_PORTS;
        
        if (args.length > 0) {
            cidr = args[0];
        }
        
        if (args.length > 1) {
            // Parse custom ports
            ports = new ArrayList<>();
            for (String port : args[1].split(",")) {
                try {
                    ports.add(Integer.parseInt(port.trim()));
                } catch (NumberFormatException e) {
                    System.err.println("Invalid port: " + port);
                }
            }
        }
        
        System.out.println("Network Scanner Starting...");
        System.out.println("Target: " + cidr);
        System.out.println("Ports to scan: " + ports.size());
        System.out.println();
        
        try {
            scanner.scanCIDR(cidr, ports);
            scanner.printStatistics();
            
            // Export results
            String filename = "scan_results_" + 
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + 
                ".csv";
            scanner.exportToCSV(filename);
            
        } catch (UnknownHostException e) {
            System.err.println("Invalid CIDR range: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error exporting results: " + e.getMessage());
        }
    }
}
