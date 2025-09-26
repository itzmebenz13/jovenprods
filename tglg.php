<?php
// Early session init and secure redirect handling BEFORE any output
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/auth_helper.php';
initializeSession();

// Require authentication for TEMU generator
requireAuth();

// Security functions
function secureEncode($data) {
    return base64_encode(gzcompress(serialize($data), 9));
}

function secureDecode($data) {
    return unserialize(gzuncompress(base64_decode($data)));
}

// Handle secure redirect early to avoid any HTML output interfering
if (isset($_GET['secure_redirect'])) {
    if (!empty($_SESSION['gift_link'])) {
        $decoded = @secureDecode($_SESSION['gift_link']);
        $decoded = is_string($decoded) ? trim($decoded) : '';
        
        if ($decoded !== '' && strpos($decoded, 'http') === 0) {
            // Clear the session data to prevent infinite redirects
            unset($_SESSION['gift_link']);
            
            // Direct redirect for both mobile and desktop
            header('Location: ' . $decoded, true, 302);
            header('Cache-Control: no-cache, no-store, must-revalidate');
            header('Pragma: no-cache');
            header('Expires: 0');
            exit;
        }
        
        // Clear invalid session data
        unset($_SESSION['gift_link']);
        header('Content-Type: text/plain; charset=UTF-8');
        echo 'error';
        exit;
    }
    
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'no_session';
    exit;
}

// Include tool access control (this will handle session initialization for normal page flow)
require_once __DIR__ . '/includes/tool_access.php';

// Check if user has access to TEMU Gift Generator - redirect to login if not
if (!checkTemuAccess(false)) {
    header('Location: index.php');
    exit;
}

// Enhanced device detection function
function isMobileDevice() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    // Mobile keywords detection
    $mobileKeywords = [
        'Mobile', 'Android', 'iPhone', 'iPad', 'iPod', 'BlackBerry', 
        'Windows Phone', 'Opera Mini', 'IEMobile', 'Mobile Safari',
        'webOS', 'Kindle', 'Silk', 'BB10', 'PlayBook'
    ];
    
    // Desktop keywords that should be blocked
    $desktopKeywords = [
        'Windows NT', 'Macintosh', 'Linux', 'Ubuntu', 'X11', 
        'Chrome/', 'Firefox/', 'Safari/', 'Edge/', 'Opera/'
    ];
    
    $mobileDetected = false;
    $desktopDetected = false;
    
    foreach ($mobileKeywords as $keyword) {
        if (stripos($userAgent, $keyword) !== false) {
            $mobileDetected = true;
            break;
        }
    }
    
    // Check for desktop indicators
    foreach ($desktopKeywords as $keyword) {
        if (stripos($userAgent, $keyword) !== false && !$mobileDetected) {
            $desktopDetected = true;
            break;
        }
    }
    
    // Additional check for suspicious user agents
    if (empty($userAgent) || strlen($userAgent) < 10) {
        return false; // Suspicious or missing user agent
    }
    
    return $mobileDetected && !$desktopDetected;
}

// TEMU Link Processing Variables
$error = '';
$success = '';
$show_result = false;
$display_goods_id = '';
$token_error = false;

// Database connection for token operations
$conn = new mysqli(DB_SERVER, DB_USER, DB_PASS, DB_NAME);

// Create timed_access table if it doesn't exist
$create_timed_access = "CREATE TABLE IF NOT EXISTS timed_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    access_type ENUM('5min', '15min') NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_active (user_id, is_active, end_time)
)";

if (!$conn->connect_error) {
    $conn->query($create_timed_access);
}

// Create permanent_access table for lifetime unlimited access
$create_permanent_access = "CREATE TABLE IF NOT EXISTS permanent_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    access_type ENUM('lifetime') NOT NULL DEFAULT 'lifetime',
    purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    amount_paid DECIMAL(10,2) NOT NULL DEFAULT 299.00,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_permanent (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";

if (!$conn->connect_error) {
    $conn->query($create_permanent_access);
}

// Helper functions for token operations
function getUserTokens($conn, $user_id) {
    $stmt = $conn->prepare("SELECT tokens FROM user_tokens WHERE user_id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            return $result->fetch_assoc()['tokens'];
        }
    }
    return 0;
}

function getActiveTimedAccess($conn, $user_id) {
    $stmt = $conn->prepare("SELECT * FROM timed_access WHERE user_id = ? AND is_active = 1 AND end_time > NOW() ORDER BY end_time DESC LIMIT 1");
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            return $result->fetch_assoc();
        }
    }
    return null;
}

function createTimedAccess($conn, $user_id, $access_type) {
    $minutes = ($access_type === '5min') ? 5 : 15;
    
    $stmt = $conn->prepare("INSERT INTO timed_access (user_id, access_type, end_time) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))");
    if ($stmt) {
        $stmt->bind_param("isi", $user_id, $access_type, $minutes);
        return $stmt->execute();
    }
    return false;
}

function hasPermanentAccess($conn, $user_id) {
    $stmt = $conn->prepare("SELECT * FROM permanent_access WHERE user_id = ? AND is_active = 1");
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->num_rows > 0 ? $result->fetch_assoc() : null;
    }
    return null;
}

function createPermanentAccess($conn, $user_id, $amount_paid = 299.00) {
    $stmt = $conn->prepare("INSERT INTO permanent_access (user_id, amount_paid) VALUES (?, ?)");
    if ($stmt) {
        $stmt->bind_param("id", $user_id, $amount_paid);
        return $stmt->execute();
    }
    return false;
}

function deactivateExpiredAccess($conn, $user_id) {
    $stmt = $conn->prepare("UPDATE timed_access SET is_active = 0 WHERE user_id = ? AND end_time <= NOW() AND is_active = 1");
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
    }
}

function checkDailyFreeGenerates($conn, $user_id) {
    $today = date('Y-m-d');
    $stmt = $conn->prepare("SELECT free_generates_used FROM daily_generates WHERE user_id = ? AND generate_date = ?");
    if ($stmt) {
        $stmt->bind_param("is", $user_id, $today);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            return $result->fetch_assoc()['free_generates_used'];
        }
    }
    return 0;
}

function consumeGenerate($conn, $user_id) {
    // Check for permanent unlimited access first (highest priority)
    $permanent_access = hasPermanentAccess($conn, $user_id);
    if ($permanent_access) {
        // User has lifetime unlimited access - no need to consume anything
        return true;
    }
    
    // Clean up any expired timed access
    deactivateExpiredAccess($conn, $user_id);
    
    // Check for active timed access (piso wifi style)
    $timed_access = getActiveTimedAccess($conn, $user_id);
    if ($timed_access) {
        // User has unlimited access during their time - no need to consume anything
        return true;
    }
    
    // Check free daily generates
    $free_generates_used = checkDailyFreeGenerates($conn, $user_id);
    $free_generates_remaining = max(0, 1 - $free_generates_used);
    
    if ($free_generates_remaining > 0) {
        // Use free generate
        $today = date('Y-m-d');
        $stmt = $conn->prepare("INSERT INTO daily_generates (user_id, generate_date, free_generates_used) 
                               VALUES (?, ?, 1) 
                               ON DUPLICATE KEY UPDATE free_generates_used = free_generates_used + 1");
        if ($stmt) {
            $stmt->bind_param("is", $user_id, $today);
            return $stmt->execute();
        }
    } else {
        $tokens = getUserTokens($conn, $user_id);
        if ($tokens > 0) {
            // Use token
            $stmt = $conn->prepare("UPDATE user_tokens SET tokens = tokens - 1, total_used = total_used + 1 WHERE user_id = ?");
            if ($stmt) {
                $stmt->bind_param("i", $user_id);
                return $stmt->execute();
            }
        }
    }
    return false;
}

// Check token availability before processing
if (!empty($_POST['share_link'])) {
    // First check if user has tokens or free generates available
    $user_id = $_SESSION['user_id'];
    
    if (!$conn->connect_error) {
        // Check for permanent unlimited access first
        $permanent_access = hasPermanentAccess($conn, $user_id);
        
        if (!$permanent_access) {
            // No permanent access, check timed access
            deactivateExpiredAccess($conn, $user_id);
            $timed_access = getActiveTimedAccess($conn, $user_id);
            
            if (!$timed_access) {
                // No timed access, check other methods
                $tokens = getUserTokens($conn, $user_id);
                $free_generates_used = checkDailyFreeGenerates($conn, $user_id);
                $free_generates_remaining = max(0, 1 - $free_generates_used);
                
                if ($free_generates_remaining == 0 && $tokens == 0) {
                    $error = "You don't have any free generates, tokens, timed access, or permanent access remaining. Purchase access to continue generating gift links.";
                    $token_error = true;
                }
            }
        }
        // If permanent or timed access exists, user can generate unlimited, so no error
    }
}

// Process form submission
if (!empty($_POST['share_link']) && !$token_error) {
    $share_link = trim($_POST['share_link']);
    $generator_type = isset($_POST['generator_type']) ? $_POST['generator_type'] : 'standard'; // Default to standard for original form
    
    // Server-side validation
    if (empty($share_link)) {
        $error = "Please provide a TEMU share link.";
    } elseif (!filter_var($share_link, FILTER_VALIDATE_URL)) {
        $error = "Please provide a valid URL format.";
    } elseif (stripos($share_link, 'temu.com') === false) {
        $error = "Please provide a valid TEMU share link. The URL must contain 'temu.com'.";
    } else {
        // Function to resolve redirects and get final URL with retry logic
        function getRedirectUrl($url, $max_retries = 3) {
            $user_agents = [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Android 11; Mobile; rv:94.0) Gecko/94.0 Firefox/94.0',
                'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1'
            ];
            
            for ($attempt = 1; $attempt <= $max_retries; $attempt++) {
                $ch = curl_init();
                
                // Rotate user agents for each attempt
                $user_agent = $user_agents[($attempt - 1) % count($user_agents)];
                
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_HEADER => true,
                    CURLOPT_NOBODY => true,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_MAXREDIRS => 10,
                    CURLOPT_TIMEOUT => 45, // Increased timeout
                    CURLOPT_CONNECTTIMEOUT => 30, // Connection timeout
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false,
                    CURLOPT_USERAGENT => $user_agent,
                    CURLOPT_HTTPHEADER => [
                        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language: en-US,en;q=0.5',
                        'Accept-Encoding: gzip, deflate',
                        'DNT: 1',
                        'Connection: keep-alive',
                        'Upgrade-Insecure-Requests: 1'
                    ],
                    CURLOPT_ENCODING => '', // Enable compression
                    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4 // Force IPv4
                ]);
                
                $response = curl_exec($ch);
                $final_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curl_error = curl_error($ch);
                curl_close($ch);
                
                // Success conditions
                if ($response !== false && $http_code >= 200 && $http_code < 400 && empty($curl_error)) {
                    return $final_url;
                }
                
                // Log the attempt for debugging (optional)
                error_log("TEMU Link Generator - Attempt $attempt failed. HTTP Code: $http_code, cURL Error: $curl_error");
                
                // Wait before retry (progressive backoff)
                if ($attempt < $max_retries) {
                    usleep(500000 * $attempt); // 0.5, 1.0, 1.5 seconds delay
                }
            }
            
            return false;
        }
        
        $extracted_link = getRedirectUrl($share_link);
        
        if ($extracted_link) {
            // Extract goods_id from the final URL
            if (preg_match('/goods_id=([^&]+)/', $extracted_link, $matches)) {
                $goods_id = $matches[1];
                $gift_link = '';
                
                // Generate different types of links based on generator type
                if ($generator_type === 'full_return') {
                    // Full Return Activity Link Template - simplified to avoid encoding issues
                    $gift_link = "https://app.temu.com/bgnb_all_return.html?_bg_fs=1&_activity_type=FULL_RETURN&_mkt_usr_p_from=PUSH&_x_nw_usr_trace_id=3420149110752721920&et=" . (time() * 1000) . "&_x_mkt_acty_trace_id=7565616451834381312&_x_mkt_algo_dist_id=db3e20779acc464592f0df5012056ae5&nz_goods=[" . $goods_id . "]&_g_i_codes=[%22" . $goods_id . "_%25262562233096%2526%2526%2526%2526-1%22]&site_id=127&mmid=bab57976c44b403ea3579926e2f9d1ddCHN2&_x_chat_msg_id=1734523823863026&_x_sessn_id=7m3s2g99co&refer_page_name=message_box&refer_page_id=10080_1734526286662_hj0l5rk2ct&refer_page_sn=10080";
                } else {
                    // Standard Gift Link Template (default)
                    $gift_link = "https://app.temu.com/ph-en/kuiper/un1.html?subj=feed-un&_bg_fs=1&_p_mat1_type=3&_p_jump_id=722&_x_vst_scene=adg&goods_id=" . $goods_id;
                }
                
                // Consume token or free generate before storing the link
                if (consumeGenerate($conn, $user_id)) {
                    // Store the gift link securely for redirection
                    $_SESSION['gift_link'] = secureEncode($gift_link);
                    
                    $generator_name = ($generator_type === 'full_return') ? 'Full Return' : 'Standard';
                    $success = $generator_name . " gift link generated successfully!";
                    $show_result = true;
                    $display_goods_id = $goods_id; // Make available for result display
                } else {
                    $error = 'Failed to consume token/free generate';
                }
            } else {
                $error = "Could not extract product ID from the TEMU link. Please verify that you're using a valid TEMU product share link.";
            }
        } else {
            $error = "Unable to process the TEMU link after multiple attempts. This could be due to network issues or the link format. Please try again or verify that your link is a valid TEMU share URL (should contain 'temu.com' or 'share.temu.com').";
        }
    }
}

// Close database connection
if ($conn && !$conn->connect_error) {
    $conn->close();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TEMU Gift Generator // Active Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            font-family: 'Space Mono', monospace;
            background-color: #0a0a0a;
            color: #e0e0e0;
            position: relative;
        }

        /* Canvas for new background animation */
        #particle-canvas {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
        }

        /* Scanline Overlay remains for texture */
        .scanline-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(0deg, rgba(0,0,0,0) 0%, rgba(0,0,0,0.2) 50%, rgba(0,0,0,0) 100%);
            background-size: 100% 4px;
            animation: scanline 10s linear infinite;
            z-index: 0;
        }
        
        @keyframes scanline {
            from { background-position: 0 0; }
            to { background-position: 0 100%; }
        }

        .glitch {
            /* Responsive font size */
            font-size: 2.25rem; /* 36px for mobile */
            line-height: 1;
            font-weight: 700;
            position: relative;
            color: #fff;
            animation: glitch-skew 1.5s infinite linear alternate-reverse;
        }
        
        @media (min-width: 640px) {
            .glitch {
                font-size: 3rem; /* 48px for sm screens and up */
            }
        }

        .glitch::before,
        .glitch::after {
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #0a0a0a;
            overflow: hidden;
        }

        /* Subtler Glitch Effect */
        .glitch::before {
            left: 1px;
            text-shadow: -1px 0 #ff00c1;
            animation: glitch-anim-subtle 5s infinite linear alternate-reverse;
        }

        .glitch::after {
            left: -1px;
            text-shadow: -1px 0 #00fff9, 1px 1px #ff00c1;
            animation: glitch-anim-subtle-2 7s infinite linear alternate-reverse;
        }

        @keyframes glitch-skew {
            0%, 100% { transform: skewX(0deg); }
            95% { transform: skewX(0deg); }
            96% { transform: skewX(0.5deg); }
            98% { transform: skewX(-0.25deg); }
            99% { transform: skewX(0deg); }
        }

        @keyframes glitch-anim-subtle {
            0%, 100% { clip-path: polygon(0 45%, 100% 45%, 100% 55%, 0 55%); }
            48% { clip-path: polygon(0 45%, 100% 45%, 100% 55%, 0 55%); }
            50% { clip-path: polygon(0 20%, 100% 20%, 100% 80%, 0 80%); }
            52% { clip-path: polygon(0 45%, 100% 45%, 100% 55%, 0 55%); }
        }

        @keyframes glitch-anim-subtle-2 {
            0%, 100% { clip-path: polygon(0 50%, 100% 50%, 100% 60%, 0 60%); }
            33% { clip-path: polygon(0 50%, 100% 50%, 100% 60%, 0 60%); }
            35% { clip-path: polygon(0 10%, 100% 10%, 100% 90%, 0 90%); }
            37% { clip-path: polygon(0 50%, 100% 50%, 100% 60%, 0 60%); }
        }

        /* Blinking Cursor */
        .blinking-cursor {
            display: inline-block;
            background-color: #e0e0e0;
            width: 10px;
            height: 1.2rem;
            margin-left: 4px;
            animation: blink 1s step-end infinite;
        }

        @keyframes blink {
            from, to { background-color: transparent; }
            50% { background-color: #e0e0e0; }
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
        }

        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
            animation: modalFadeIn 0.3s ease-out;
        }

        @keyframes modalFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .modal-content {
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            margin: 15% auto;
            padding: 32px;
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 16px;
            width: 90%;
            max-width: 500px;
            position: relative;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5), 0 0 30px rgba(0, 255, 249, 0.2);
            text-align: center;
            animation: modalSlideIn 0.3s ease-out;
        }

        @keyframes modalSlideIn {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .modal-content.success {
            border-color: rgba(0, 255, 249, 0.5);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5), 0 0 30px rgba(0, 255, 249, 0.3);
        }

        .modal-content.error {
            border-color: rgba(255, 0, 156, 0.5);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5), 0 0 30px rgba(255, 0, 156, 0.3);
        }

        .modal-close {
            position: absolute;
            top: 16px;
            right: 20px;
            color: #aaa;
            font-size: 24px;
            font-weight: bold;
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .modal-close:hover {
            color: #fff;
        }

        .modal-icon {
            font-size: 48px;
            margin-bottom: 16px;
            display: block;
        }

        .modal-icon.success {
            color: #00fff9;
        }

        .modal-icon.error {
            color: #ff00c1;
        }

        .modal-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 16px;
            color: #fff;
        }

        .modal-message {
            font-size: 1rem;
            color: #ccc;
            line-height: 1.6;
            margin-bottom: 8px;
        }

        .modal-submessage {
            font-size: 0.875rem;
            color: #999;
            line-height: 1.5;
        }

        .generated-link {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            text-decoration: none;
            padding: 14px 24px;
            border-radius: 12px;
            display: inline-block;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            margin-top: 16px;
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
            position: relative;
            overflow: hidden;
            letter-spacing: 0.025em;
        }

        .generated-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 28px rgba(16, 185, 129, 0.4);
            text-decoration: none;
            color: white;
        }

        /* Auto Processing Status */
        .auto-status {
            display: none;
            margin-bottom: 16px;
            padding: 12px;
            background: rgba(0, 255, 249, 0.1);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 8px;
            text-align: center;
            white-space: nowrap;
            overflow: hidden;
        }

        .auto-status.show {
            display: block;
            animation: fadeInUp 0.5s ease-out;
        }

        .auto-status .text-sm {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: inline-block;
            max-width: 100%;
        }

        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Enhanced Loading Animation */
        .btn-loading {
            cursor: not-allowed !important;
            pointer-events: none;
            position: relative !important;
            overflow: hidden !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 8px !important;
        }

        /* Standard Loading (Cyan Theme) */
        .btn-loading.standard {
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a) !important;
            border: 2px solid transparent !important;
            color: #00fff9 !important;
        }

        .btn-loading.standard::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 249, 0.4), transparent);
            animation: shimmer 1.5s infinite;
        }

        /* Full Return Loading (Purple/Pink Theme) */
        .btn-loading.full-return {
            background: linear-gradient(135deg, #4c1d95, #7c2d12) !important;
            border: 2px solid transparent !important;
            color: #e879f9 !important;
        }

        .btn-loading.full-return::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(232, 121, 249, 0.4), transparent);
            animation: shimmer 1.5s infinite;
        }

        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        .loading-dots {
            display: flex;
            align-items: center;
            gap: 3px;
            flex-shrink: 0;
        }

        .loading-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            animation: pulse-dot 1.4s ease-in-out infinite both;
        }

        .loading-dot:nth-child(1) { animation-delay: -0.32s; }
        .loading-dot:nth-child(2) { animation-delay: -0.16s; }
        .loading-dot:nth-child(3) { animation-delay: 0s; }

        /* Standard theme dots */
        .btn-loading.standard .loading-dot {
            background: #00fff9;
        }

        /* Full return theme dots */
        .btn-loading.full-return .loading-dot {
            background: #e879f9;
        }

        @keyframes pulse-dot {
            0%, 80%, 100% { 
                transform: scale(0.8);
                opacity: 0.5;
            }
            40% { 
                transform: scale(1.2);
                opacity: 1;
            }
        }

        /* Standard theme pulse glow */
        .btn-loading.standard .loading-dot {
            animation: pulse-dot-cyan 1.4s ease-in-out infinite both;
        }

        .btn-loading.full-return .loading-dot {
            animation: pulse-dot-purple 1.4s ease-in-out infinite both;
        }

        @keyframes pulse-dot-cyan {
            0%, 80%, 100% { 
                transform: scale(0.8);
                opacity: 0.5;
            }
            40% { 
                transform: scale(1.2);
                opacity: 1;
                box-shadow: 0 0 8px #00fff9;
            }
        }

        @keyframes pulse-dot-purple {
            0%, 80%, 100% { 
                transform: scale(0.8);
                opacity: 0.5;
            }
            40% { 
                transform: scale(1.2);
                opacity: 1;
                box-shadow: 0 0 8px #e879f9;
            }
        }

        .loading-circuit {
            display: flex;
            width: 20px;
            height: 20px;
            position: relative;
            flex-shrink: 0;
        }

        .loading-circuit::before,
        .loading-circuit::after {
            content: '';
            position: absolute;
            width: 16px;
            height: 16px;
            border: 2px solid transparent;
            border-radius: 50%;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }

        /* Standard theme circuit */
        .btn-loading.standard .loading-circuit::before {
            border-top: 2px solid #00fff9;
            border-right: 2px solid #00fff9;
            animation: circuit-rotate 1s linear infinite;
        }

        .btn-loading.standard .loading-circuit::after {
            border-bottom: 2px solid #ff00c1;
            border-left: 2px solid #ff00c1;
            animation: circuit-rotate 1s linear infinite reverse;
        }

        /* Full return theme circuit */
        .btn-loading.full-return .loading-circuit::before {
            border-top: 2px solid #e879f9;
            border-right: 2px solid #e879f9;
            animation: circuit-rotate 1s linear infinite;
        }

        .btn-loading.full-return .loading-circuit::after {
            border-bottom: 2px solid #f97316;
            border-left: 2px solid #f97316;
            animation: circuit-rotate 1s linear infinite reverse;
        }

        @keyframes circuit-rotate {
            0% { transform: translate(-50%, -50%) rotate(0deg); }
            100% { transform: translate(-50%, -50%) rotate(360deg); }
        }

        .loading-text {
            font-weight: 600;
            letter-spacing: 1px;
            white-space: nowrap;
            flex-shrink: 0;
            background-size: 200% 200%;
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradient-shift 2s ease-in-out infinite;
        }

        /* Standard theme text */
        .btn-loading.standard .loading-text {
            background: linear-gradient(45deg, #00fff9, #ff00c1, #00fff9);
        }

        /* Full return theme text */
        .btn-loading.full-return .loading-text {
            background: linear-gradient(45deg, #e879f9, #f97316, #e879f9);
        }

        @keyframes gradient-shift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }

        /* Enhanced message notifications */
        .temp-message {
            will-change: transform, opacity;
        }

        .temp-message .backdrop-blur-lg {
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
        }

        .temp-message button:hover {
            transform: scale(1.1);
        }

        /* Volume Slider Styling */
        .slider {
            -webkit-appearance: none;
            appearance: none;
            background: #4a5568;
            outline: none;
        }

        .slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #9f7aea;
            cursor: pointer;
        }

        .slider::-moz-range-thumb {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #9f7aea;
            cursor: pointer;
            border: none;
        }

        /* Cyberpunk Preloader Styles */
        #cyberpunk-preloader {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #0a0a0a, #1a0033, #000a1a);
            z-index: 9999;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        /* Animated Grid Background */
        .cyber-grid {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 255, 249, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 249, 0.1) 1px, transparent 1px),
                linear-gradient(rgba(255, 0, 196, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 0, 196, 0.05) 1px, transparent 1px);
            background-size: 100px 100px, 100px 100px, 20px 20px, 20px 20px;
            animation: grid-move 4s linear infinite;
            opacity: 0.3;
        }

        @keyframes grid-move {
            0% { transform: translate(0, 0); }
            100% { transform: translate(100px, 100px); }
        }

        /* Enhanced Particle System */
        .cyber-particles {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
        }

        .cyber-particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: #00fff9;
            border-radius: 50%;
            animation: particle-float linear infinite;
            box-shadow: 0 0 4px #00fff9;
        }

        .cyber-particle.pink {
            background: #ff00c1;
            box-shadow: 0 0 4px #ff00c1;
        }

        @keyframes particle-float {
            0% {
                opacity: 0;
                transform: translateY(100vh) scale(0);
            }
            10% {
                opacity: 1;
                transform: translateY(90vh) scale(1);
            }
            90% {
                opacity: 1;
                transform: translateY(10vh) scale(1);
            }
            100% {
                opacity: 0;
                transform: translateY(-10vh) scale(0);
            }
        }

        /* Enhanced Central Loading Animation */
        .cyber-loader {
            position: relative;
            width: 200px;
            height: 200px;
            margin-bottom: 40px;
            filter: drop-shadow(0 0 20px rgba(0, 255, 249, 0.3));
        }

        .cyber-circle {
            position: absolute;
            width: 100%;
            height: 100%;
            border: 3px solid transparent;
            border-radius: 50%;
            animation: cyber-rotate 2s linear infinite;
        }

        .cyber-circle:nth-child(1) {
            border-top-color: #00fff9;
            border-right-color: #00fff9;
            animation-duration: 0.8s;
            box-shadow: 
                0 0 20px rgba(0, 255, 249, 0.5),
                inset 0 0 20px rgba(0, 255, 249, 0.1);
        }

        .cyber-circle:nth-child(2) {
            border-bottom-color: #ff00c1;
            border-left-color: #ff00c1;
            animation-duration: 1.5s;
            animation-direction: reverse;
            width: 85%;
            height: 85%;
            top: 7.5%;
            left: 7.5%;
            box-shadow: 
                0 0 15px rgba(255, 0, 193, 0.5),
                inset 0 0 15px rgba(255, 0, 193, 0.1);
        }

        .cyber-circle:nth-child(3) {
            border-top-color: #fff;
            border-bottom-color: #fff;
            animation-duration: 1.2s;
            width: 70%;
            height: 70%;
            top: 15%;
            left: 15%;
            box-shadow: 
                0 0 10px rgba(255, 255, 255, 0.3),
                inset 0 0 10px rgba(255, 255, 255, 0.1);
        }

        .cyber-circle:nth-child(4) {
            border-left-color: #00ff88;
            border-right-color: #00ff88;
            animation-duration: 2.5s;
            width: 55%;
            height: 55%;
            top: 22.5%;
            left: 22.5%;
            box-shadow: 0 0 8px rgba(0, 255, 136, 0.4);
        }

        @keyframes cyber-rotate {
            0% { 
                transform: rotate(0deg);
                filter: brightness(1);
            }
            25% { 
                filter: brightness(1.2);
            }
            50% { 
                transform: rotate(180deg);
                filter: brightness(1);
            }
            75% { 
                filter: brightness(1.2);
            }
            100% { 
                transform: rotate(360deg);
                filter: brightness(1);
            }
        }

        /* Enhanced Central Core */
        .cyber-core {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 80px;
            height: 80px;
            background: 
                radial-gradient(circle at 30% 30%, #ffffff, transparent 50%),
                radial-gradient(circle, #00fff9 20%, #ff00c1 50%, #9d4edd 80%);
            border-radius: 50%;
            animation: cyber-pulse-enhanced 2s ease-in-out infinite;
            box-shadow: 
                0 0 30px #00fff9,
                0 0 60px #ff00c1,
                0 0 90px rgba(0, 255, 249, 0.3),
                inset 0 0 20px rgba(255, 255, 255, 0.1);
            position: relative;
        }

        .cyber-core::before {
            content: '';
            position: absolute;
            top: -10px;
            left: -10px;
            right: -10px;
            bottom: -10px;
            border-radius: 50%;
            background: conic-gradient(
                from 0deg,
                transparent 0deg,
                #00fff9 90deg,
                transparent 180deg,
                #ff00c1 270deg,
                transparent 360deg
            );
            animation: cyber-core-ring 3s linear infinite;
            opacity: 0.6;
        }

        .cyber-core::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 40px;
            height: 40px;
            background: radial-gradient(circle, #ffffff 20%, transparent 70%);
            border-radius: 50%;
            animation: cyber-core-inner 1.5s ease-in-out infinite alternate;
        }

        @keyframes cyber-pulse-enhanced {
            0% { 
                transform: translate(-50%, -50%) scale(0.9);
                opacity: 0.8;
                filter: brightness(1) saturate(1);
            }
            25% {
                transform: translate(-50%, -50%) scale(1.05);
                filter: brightness(1.2) saturate(1.3);
            }
            50% { 
                transform: translate(-50%, -50%) scale(1.1);
                opacity: 1;
                filter: brightness(1.4) saturate(1.5);
            }
            75% {
                transform: translate(-50%, -50%) scale(1.05);
                filter: brightness(1.2) saturate(1.3);
            }
            100% { 
                transform: translate(-50%, -50%) scale(0.9);
                opacity: 0.8;
                filter: brightness(1) saturate(1);
            }
        }

        @keyframes cyber-core-ring {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes cyber-core-inner {
            0% { 
                opacity: 0.3; 
                transform: translate(-50%, -50%) scale(0.8);
            }
            100% { 
                opacity: 0.8; 
                transform: translate(-50%, -50%) scale(1.2);
            }
        }

        /* Enhanced Glitch Text */
        .cyber-text {
            font-family: 'Space Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
            color: #fff;
            text-transform: uppercase;
            letter-spacing: 4px;
            margin-bottom: 20px;
            position: relative;
            animation: cyber-glitch-enhanced 4s linear infinite;
            text-shadow: 
                0 0 10px rgba(255, 255, 255, 0.3),
                0 0 20px rgba(0, 255, 249, 0.2),
                0 0 30px rgba(255, 0, 193, 0.2);
            filter: drop-shadow(0 0 10px rgba(0, 255, 249, 0.5));
        }

        .cyber-text::before,
        .cyber-text::after {
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            mix-blend-mode: screen;
        }

        .cyber-text::before {
            color: #00fff9;
            animation: cyber-glitch-advanced-1 2s infinite;
            clip-path: polygon(0 0, 100% 0, 100% 35%, 0 35%);
            text-shadow: 0 0 15px #00fff9;
        }

        .cyber-text::after {
            color: #ff00c1;
            animation: cyber-glitch-advanced-2 2.5s infinite;
            clip-path: polygon(0 65%, 100% 65%, 100% 100%, 0 100%);
            text-shadow: 0 0 15px #ff00c1;
        }

        @keyframes cyber-glitch-enhanced {
            0%, 85%, 100% { 
                transform: translate(0);
                filter: brightness(1) contrast(1);
            }
            86% { 
                transform: translate(-2px, -1px);
                filter: brightness(1.5) contrast(1.2);
            }
            87% { 
                transform: translate(2px, 1px);
                filter: brightness(0.8) contrast(1.5);
            }
            88% { 
                transform: translate(-1px, 2px);
                filter: brightness(1.2) contrast(0.9);
            }
            89% { 
                transform: translate(1px, -1px);
                filter: brightness(1.3) contrast(1.1);
            }
            90% { 
                transform: translate(0);
                filter: brightness(1) contrast(1);
            }
        }

        @keyframes cyber-glitch-advanced-1 {
            0%, 80%, 100% { 
                transform: translate(0);
                opacity: 0.8;
            }
            81% { 
                transform: translate(3px, 0);
                opacity: 1;
                clip-path: polygon(0 0, 100% 0, 100% 25%, 0 25%);
            }
            83% { 
                transform: translate(-2px, 0);
                clip-path: polygon(0 40%, 100% 40%, 100% 60%, 0 60%);
            }
            85% { 
                transform: translate(1px, 0);
                clip-path: polygon(0 0, 100% 0, 100% 35%, 0 35%);
            }
        }

        @keyframes cyber-glitch-advanced-2 {
            0%, 75%, 100% { 
                transform: translate(0);
                opacity: 0.8;
            }
            76% { 
                transform: translate(-3px, 0);
                opacity: 1;
                clip-path: polygon(0 70%, 100% 70%, 100% 100%, 0 100%);
            }
            78% { 
                transform: translate(2px, 0);
                clip-path: polygon(0 50%, 100% 50%, 100% 80%, 0 80%);
            }
            80% { 
                transform: translate(-1px, 0);
                clip-path: polygon(0 65%, 100% 65%, 100% 100%, 0 100%);
            }
        }

        /* Loading Progress */
        .cyber-progress {
            width: 300px;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 20px;
        }

        .cyber-progress-bar {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #00fff9, #ff00c1, #00fff9);
            background-size: 200% 100%;
            animation: progress-fill 3s ease-out forwards, progress-glow 1s ease-in-out infinite alternate;
            border-radius: 2px;
        }

        @keyframes progress-fill {
            0% { width: 0%; }
            100% { width: 100%; }
        }

        @keyframes progress-glow {
            0% { background-position: 0% 0%; box-shadow: 0 0 5px #00fff9; }
            100% { background-position: 200% 0%; box-shadow: 0 0 10px #ff00c1; }
        }

        /* Status Text */
        .cyber-status {
            color: #00fff9;
            font-family: 'Space Mono', monospace;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            animation: cyber-typing 1s steps(20) infinite;
        }

        @keyframes cyber-typing {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }

        /* Enhanced Circuit Lines */
        .circuit-lines {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.4;
            z-index: 1;
        }

        .circuit-line {
            position: absolute;
            animation: circuit-flow-enhanced 3s linear infinite;
        }

        .circuit-line.horizontal {
            height: 2px;
            width: 100%;
            left: 0;
            background: linear-gradient(90deg, 
                transparent 0%, 
                rgba(0, 255, 249, 0.1) 20%, 
                #00fff9 50%, 
                rgba(0, 255, 249, 0.1) 80%, 
                transparent 100%);
            box-shadow: 0 0 4px rgba(0, 255, 249, 0.5);
        }

        .circuit-line.vertical {
            width: 2px;
            height: 100%;
            top: 0;
            background: linear-gradient(180deg, 
                transparent 0%, 
                rgba(255, 0, 193, 0.1) 20%, 
                #ff00c1 50%, 
                rgba(255, 0, 193, 0.1) 80%, 
                transparent 100%);
            box-shadow: 0 0 4px rgba(255, 0, 193, 0.5);
        }

        .circuit-line:nth-child(1) { top: 15%; animation-delay: 0s; }
        .circuit-line:nth-child(2) { top: 35%; animation-delay: 0.8s; }
        .circuit-line:nth-child(3) { top: 55%; animation-delay: 1.6s; }
        .circuit-line:nth-child(4) { top: 75%; animation-delay: 2.4s; }
        .circuit-line:nth-child(5) { left: 15%; animation-delay: 0.4s; }
        .circuit-line:nth-child(6) { left: 35%; animation-delay: 1.2s; }
        .circuit-line:nth-child(7) { left: 55%; animation-delay: 2s; }
        .circuit-line:nth-child(8) { left: 75%; animation-delay: 2.8s; }

        .circuit-line.diagonal {
            width: 200px;
            height: 2px;
            background: linear-gradient(90deg, 
                transparent 0%, 
                rgba(0, 255, 136, 0.1) 20%, 
                #00ff88 50%, 
                rgba(0, 255, 136, 0.1) 80%, 
                transparent 100%);
            transform: rotate(45deg);
            top: 50%;
            left: 10%;
            animation-delay: 1.5s;
            box-shadow: 0 0 4px rgba(0, 255, 136, 0.5);
        }

        @keyframes circuit-flow-enhanced {
            0% { 
                opacity: 0; 
                transform: scaleX(0) scaleY(1);
                filter: brightness(0.5);
            }
            25% { 
                opacity: 0.7; 
                transform: scaleX(0.5) scaleY(1.2);
                filter: brightness(1.2);
            }
            50% { 
                opacity: 1; 
                transform: scaleX(1) scaleY(1.5);
                filter: brightness(1.5);
            }
            75% { 
                opacity: 0.7; 
                transform: scaleX(0.5) scaleY(1.2);
                filter: brightness(1.2);
            }
            100% { 
                opacity: 0; 
                transform: scaleX(0) scaleY(1);
                filter: brightness(0.5);
            }
        }

        /* Hide preloader when page is loaded */
        .preloader-hidden {
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.5s ease-out, visibility 0.5s ease-out;
        }

        /* Compact Chat System Styles */
        #chat-toggle-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 45px;
            height: 45px;
            background: linear-gradient(135deg, #00fff9, #0099cc);
            border: 1px solid rgba(0, 255, 249, 0.5);
            border-radius: 50%;
            color: #000;
            font-size: 16px;
            cursor: pointer;
            z-index: 1001;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 2px 10px rgba(0, 255, 249, 0.4);
        }

        #chat-toggle-btn:hover {
            background: linear-gradient(135deg, #00ccff, #0077aa);
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(0, 255, 249, 0.5);
        }

        #full-chat-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            z-index: 1002;
            opacity: 0;
            transition: opacity 0.3s ease;
            padding: 15px;
            box-sizing: border-box;
        }

        #full-chat-modal.show {
            display: flex;
            justify-content: center;
            align-items: center;
            opacity: 1;
        }

        .chat-container {
            width: 100%;
            max-width: 1000px;
            height: 85vh;
            background: linear-gradient(135deg, #0f0f0f, #1a1a1a);
            display: grid;
            grid-template-columns: 200px 1fr;
            border: 1px solid rgba(0, 255, 249, 0.4);
            border-radius: 12px;
            position: relative;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
            overflow: hidden;
        }

        .chat-sidebar {
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(0, 0, 0, 0.6));
            border-right: 1px solid rgba(0, 255, 249, 0.3);
            display: flex;
            flex-direction: column;
        }

        .sidebar-section {
            padding: 10px;
            border-bottom: 1px solid rgba(0, 255, 249, 0.2);
        }

        .sidebar-title {
            font-size: 11px;
            font-weight: 600;
            color: #00fff9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
            text-shadow: 0 0 3px rgba(0, 255, 249, 0.3);
        }

        .online-users {
            max-height: 150px;
            overflow-y: auto;
        }

        .online-user {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 3px 6px;
            border-radius: 4px;
            margin-bottom: 2px;
            transition: background 0.2s ease;
            cursor: pointer;
        }

        .online-user:hover {
            background: rgba(0, 255, 249, 0.1);
        }

        .user-status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #00ff88;
            box-shadow: 0 0 4px #00ff88;
        }

        .user-name {
            font-size: 10px;
            color: #ccc;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .chat-main {
            display: flex;
            flex-direction: column;
            min-width: 0;
        }

        .chat-header {
            background: linear-gradient(90deg, rgba(0, 255, 249, 0.15), rgba(255, 0, 193, 0.15));
            border-bottom: 1px solid rgba(0, 255, 249, 0.3);
            padding: 12px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            backdrop-filter: blur(5px);
            flex-shrink: 0;
        }

        .chat-header h4 {
            margin: 0;
            font-size: 16px;
            font-weight: 600;
            color: #00fff9;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-shadow: 0 0 5px rgba(0, 255, 249, 0.3);
        }

        .chat-close-btn {
            background: rgba(255, 0, 0, 0.15);
            border: 1px solid rgba(255, 0, 0, 0.4);
            border-radius: 50%;
            width: 28px;
            height: 28px;
            color: #ff6b6b;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .chat-close-btn:hover {
            background: rgba(255, 0, 0, 0.25);
            transform: scale(1.05);
            box-shadow: 0 0 8px rgba(255, 0, 0, 0.2);
        }

        .chat-content {
            display: flex;
            flex-direction: column;
            flex: 1;
            min-height: 0;
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 12px;
            background: rgba(0, 0, 0, 0.2);
            max-height: none;
            min-height: 0;
        }

        .chat-message {
            margin-bottom: 8px;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 13px;
            line-height: 1.4;
            max-width: 75%;
            animation: messageSlideIn 0.2s ease-out;
            position: relative;
            group: message;
        }

        .chat-message:hover .message-actions {
            opacity: 1;
            visibility: visible;
        }

        .message-actions {
            position: absolute;
            top: -8px;
            right: 8px;
            display: flex;
            gap: 4px;
            opacity: 0;
            visibility: hidden;
            transition: all 0.2s ease;
            z-index: 10;
        }

        .message-action-btn {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 4px;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .message-action-btn:hover {
            background: rgba(0, 255, 249, 0.2);
            border-color: #00fff9;
        }

        .message-action-btn i {
            font-size: 10px;
            color: #00fff9;
        }

        .message-reactions {
            display: flex;
            gap: 4px;
            margin-top: 4px;
            flex-wrap: wrap;
        }

        .reaction-btn {
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 2px 6px;
            display: flex;
            align-items: center;
            gap: 3px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 10px;
        }

        .reaction-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.4);
        }

        .reaction-btn.user-reacted {
            background: rgba(0, 255, 249, 0.2);
            border-color: #00fff9;
            color: #00fff9;
        }

        .reaction-emoji {
            font-size: 11px;
        }

        .reaction-count {
            font-size: 9px;
            font-weight: 600;
            color: #ccc;
        }

        .user-reacted .reaction-count {
            color: #00fff9;
        }

        .message-edited {
            font-size: 9px;
            color: #888;
            font-style: italic;
            margin-top: 2px;
        }

        .reply-to {
            background: rgba(0, 255, 249, 0.1);
            border-left: 2px solid #00fff9;
            padding: 4px 8px;
            margin-bottom: 4px;
            border-radius: 4px;
            font-size: 11px;
            color: #ccc;
        }

        .reply-to .reply-username {
            color: #00fff9;
            font-weight: 600;
            font-size: 10px;
        }

        .typing-indicator {
            padding: 8px 12px;
            margin: 4px 0;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            font-size: 11px;
            color: #888;
            font-style: italic;
            animation: pulse 1.5s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }

        .emoji-picker {
            position: absolute;
            bottom: 100%;
            left: 0;
            background: rgba(0, 0, 0, 0.9);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 8px;
            padding: 8px;
            display: none;
            z-index: 100;
            backdrop-filter: blur(10px);
        }

        .emoji-picker.show {
            display: block;
        }

        .emoji-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 4px;
        }

        .emoji-btn {
            background: none;
            border: none;
            border-radius: 4px;
            padding: 4px;
            cursor: pointer;
            transition: background 0.2s ease;
            font-size: 14px;
        }

        .emoji-btn:hover {
            background: rgba(0, 255, 249, 0.2);
        }

        @keyframes messageSlideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .chat-message.own {
            background: linear-gradient(135deg, rgba(0, 255, 249, 0.15), rgba(0, 255, 249, 0.08));
            border-left: 2px solid #00fff9;
            margin-left: auto;
            margin-right: 0;
            box-shadow: 0 2px 8px rgba(0, 255, 249, 0.1);
        }

        .chat-message.other {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.04));
            border-left: 2px solid rgba(255, 255, 255, 0.4);
            margin-left: 0;
            margin-right: auto;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
        }

        .chat-message.token-transfer {
            background: linear-gradient(135deg, rgba(255, 193, 7, 0.15), rgba(255, 193, 7, 0.08));
            border: 1px solid #ffc107;
            text-align: center;
            font-weight: 600;
            margin: 0 auto;
            max-width: 60%;
            box-shadow: 0 2px 8px rgba(255, 193, 7, 0.15);
        }

        .message-username {
            font-weight: 600;
            color: #00fff9;
            margin-bottom: 2px;
            font-size: 11px;
            text-shadow: 0 0 3px rgba(0, 255, 249, 0.2);
        }

        .message-text {
            color: #e0e0e0;
            word-wrap: break-word;
            font-size: 13px;
        }

        .message-time {
            font-size: 10px;
            color: #888;
            margin-top: 3px;
            opacity: 0.6;
        }

        .chat-input-area {
            padding: 12px 15px;
            border-top: 1px solid rgba(0, 255, 249, 0.3);
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.4), rgba(0, 0, 0, 0.2));
            backdrop-filter: blur(5px);
            flex-shrink: 0;
        }

        .chat-input-container {
            display: flex;
            gap: 8px;
            align-items: center;
            position: relative;
        }

        .input-wrapper {
            flex: 1;
            position: relative;
        }

        #chat-input {
            width: 100%;
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 8px;
            padding: 8px 40px 8px 12px;
            color: #fff;
            font-size: 13px;
            outline: none;
            transition: all 0.3s ease;
            resize: none;
            font-family: 'Space Mono', monospace;
        }

        .emoji-toggle-btn {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 14px;
            transition: color 0.2s ease;
        }

        .emoji-toggle-btn:hover {
            color: #00fff9;
        }

        #chat-input:focus {
            border-color: #00fff9;
            box-shadow: 0 0 10px rgba(0, 255, 249, 0.2);
            background: rgba(0, 0, 0, 0.7);
        }

        #chat-input::placeholder {
            color: #666;
            font-style: italic;
        }

        .chat-send-btn {
            background: linear-gradient(135deg, #00fff9, #0099cc);
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            color: #000;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 2px 8px rgba(0, 255, 249, 0.2);
            white-space: nowrap;
        }

        .chat-send-btn:hover {
            background: linear-gradient(135deg, #00ccff, #0077aa);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 255, 249, 0.3);
        }

        .chat-send-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .token-transfer-controls {
            display: none;
            padding: 8px 0;
            border-top: 1px solid rgba(0, 255, 249, 0.2);
            margin-top: 8px;
        }

        .token-transfer-controls.show {
            display: block;
        }

        .transfer-input-group {
            display: flex;
            gap: 8px;
            margin-bottom: 6px;
        }

        .transfer-input-group input {
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid rgba(255, 193, 7, 0.4);
            border-radius: 6px;
            padding: 6px 8px;
            color: #fff;
            font-size: 12px;
            outline: none;
            transition: all 0.3s ease;
            font-family: 'Space Mono', monospace;
        }

        .transfer-input-group input:focus {
            border-color: #ffc107;
            box-shadow: 0 0 8px rgba(255, 193, 7, 0.2);
        }

        .transfer-info {
            font-size: 11px;
            color: #ffc107;
            text-align: center;
            margin-top: 4px;
            font-weight: 500;
            text-shadow: 0 0 3px rgba(255, 193, 7, 0.2);
        }

        .chat-options {
            display: flex;
            gap: 8px;
            margin-bottom: 8px;
        }

        .chat-option-btn {
            background: rgba(0, 255, 249, 0.08);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 6px;
            padding: 6px 12px;
            color: #00fff9;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .chat-option-btn:hover {
            background: rgba(0, 255, 249, 0.15);
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(0, 255, 249, 0.15);
        }

        .chat-option-btn.active {
            background: rgba(0, 255, 249, 0.2);
            border-color: #00fff9;
            box-shadow: 0 0 8px rgba(0, 255, 249, 0.2);
        }

        /* Mobile Responsive Chat */
        @media (max-width: 768px) {
            #full-chat-modal {
                padding: 8px;
            }
            
            .chat-container {
                height: 90vh;
                max-width: none;
                border-radius: 8px;
            }
            
            .chat-header {
                padding: 10px 12px;
            }
            
            .chat-header h4 {
                font-size: 14px;
            }
            
            .chat-close-btn {
                width: 24px;
                height: 24px;
                font-size: 12px;
            }
            
            .chat-messages {
                padding: 8px;
            }
            
            .chat-message {
                padding: 6px 10px;
                font-size: 12px;
                max-width: 85%;
            }
            
            .message-username {
                font-size: 10px;
            }
            
            .message-time {
                font-size: 9px;
            }
            
            .chat-input-area {
                padding: 8px 10px;
            }
            
            #chat-input {
                font-size: 12px;
                padding: 6px 10px;
            }
            
            .chat-send-btn {
                padding: 6px 12px;
                font-size: 11px;
            }
            
            .chat-option-btn {
                padding: 5px 8px;
                font-size: 10px;
            }
            
            .transfer-input-group input {
                font-size: 11px;
                padding: 5px 6px;
            }
            
            .transfer-info {
                font-size: 10px;
            }
        }

        /* Responsive Design */
        @media (max-width: 640px) {
            .cyber-text {
                font-size: 1.5rem;
                letter-spacing: 2px;
            }
            
            .cyber-loader {
                width: 150px;
                height: 150px;
            }
            
            .cyber-progress {
                width: 250px;
            }
        }

    </style>
</head>
<body class="min-h-screen p-4 pt-8">

    <!-- Enhanced Cyberpunk Preloader -->
    <div id="cyberpunk-preloader">
        <!-- Enhanced Particle System -->
        <div class="cyber-particles" id="cyber-particles"></div>
        
        <!-- Animated Grid Background -->
        <div class="cyber-grid"></div>
        
        <!-- Enhanced Circuit Lines -->
        <div class="circuit-lines">
            <div class="circuit-line horizontal"></div>
            <div class="circuit-line horizontal"></div>
            <div class="circuit-line horizontal"></div>
            <div class="circuit-line horizontal"></div>
            <div class="circuit-line vertical"></div>
            <div class="circuit-line vertical"></div>
            <div class="circuit-line vertical"></div>
            <div class="circuit-line vertical"></div>
            <div class="circuit-line diagonal"></div>
        </div>
        
        <!-- Enhanced Central Loading Animation -->
        <div class="cyber-loader">
            <div class="cyber-circle"></div>
            <div class="cyber-circle"></div>
            <div class="cyber-circle"></div>
            <div class="cyber-circle"></div>
            <div class="cyber-core"></div>
        </div>
        
        <!-- Enhanced Glitch Text -->
        <div class="cyber-text" data-text="TEMU GENERATOR">TEMU GENERATOR</div>
        
        <!-- Loading Progress -->
        <div class="cyber-progress">
            <div class="cyber-progress-bar"></div>
        </div>
        
        <!-- Enhanced Status Text -->
        <div class="cyber-status" id="cyber-status">INITIALIZING SYSTEM...</div>
    </div>

    <canvas id="particle-canvas"></canvas>
    <div class="scanline-overlay"></div>

    <div class="text-center max-w-2xl w-full relative z-10 mx-auto">

        <!-- Glitch Headline -->
        <div class="mb-8">
            <h1 class="glitch" data-text="TEMU GENERATOR">TEMU GENERATOR</h1>
        </div>
        
        <!-- Explanatory Paragraph -->
        <p class="text-sm sm:text-base text-gray-400 leading-relaxed max-w-lg mx-auto mb-6">
            Advanced TEMU gift link generator. Paste any TEMU share link and we'll create an optimized gift link for you<span class="blinking-cursor"></span>
        </p>
        
        <!-- Music Control Widget -->
        <div class="bg-black/30 backdrop-blur-sm border border-gray-700/50 rounded-lg p-3 mb-4 w-full max-w-md mx-auto">
            <div class="text-center mb-2">
                <h3 class="text-xs font-semibold text-gray-300 uppercase tracking-wide">Background Music</h3>
            </div>
            <div class="flex items-center justify-between text-sm">
                <div class="flex items-center gap-3">
                    <button id="music-toggle" class="w-8 h-8 bg-purple-500/20 hover:bg-purple-500/30 rounded-full flex items-center justify-center transition-colors">
                        <i id="music-icon" class="fas fa-play text-purple-400 text-xs"></i>
                    </button>
                    <div class="flex items-center gap-2">
                        <div class="flex items-center w-4">
                            <i id="music-status-icon" class="fas fa-music text-purple-400 text-xs"></i>
                        </div>
                        <select id="track-selector" class="bg-black/50 border border-gray-600/30 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-purple-400">
                            <option value="https://archive.org/download/losing_202508/fainted.mp3" selected>Fainted</option>
                            <option value="https://archive.org/download/losing_202508/closer.mp3">Closer</option>
                            <option value="https://archive.org/download/losing_202508/losing.mp3">Losing</option>
                            <option value="https://archive.org/download/losing_202508/last-dream.mp3">Last Dream</option>
                            <option value="https://archive.org/download/losing_202508/distant-echoes.mp3">Distant Echoes</option>
                        </select>
                        <span id="music-status-text" class="hidden"></span>
                    </div>
                </div>
                <div class="flex items-center gap-2">
                    <i class="fas fa-volume-down text-gray-400 text-xs"></i>
                    <input type="range" id="volume-slider" min="0" max="100" value="30" class="w-16 h-1 bg-gray-600 rounded-lg appearance-none cursor-pointer slider">
                </div>
            </div>
        </div>

        <!-- Ad Placement 1: After Music Control -->
        <div class="max-w-2xl mx-auto mb-6">
            <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6401000892288183"
                 crossorigin="anonymous"></script>
            <!-- TGLG -->
            <ins class="adsbygoogle"
                 style="display:block"
                 data-ad-client="ca-pub-6401000892288183"
                 data-ad-slot="9611997563"
                 data-ad-format="auto"
                 data-full-width-responsive="true"></ins>
            <script>
                 (adsbygoogle = window.adsbygoogle || []).push({});
            </script>
        </div>

        <!-- Compact Token Status -->
        <div class="bg-black/30 backdrop-blur-sm border border-gray-700/50 rounded-lg p-3 mb-6 max-w-md mx-auto">
            <!-- Permanent Access Status (hidden initially) -->
            <div id="permanent-access-status" class="hidden mb-3 p-3 bg-gradient-to-r from-emerald-500/20 to-green-500/20 border border-emerald-500/30 rounded-lg">
                <div class="flex items-center justify-center gap-2 text-sm">
                    <i class="fas fa-crown text-emerald-400"></i>
                    <span class="text-emerald-400 font-bold">LIFETIME UNLIMITED</span>
                    <div class="flex items-center gap-1 ml-2">
                        <i class="fas fa-star text-gold-400 text-xs"></i>
                        <span class="font-bold text-emerald-400 bg-black/20 px-2 py-0.5 rounded text-xs">
                            PREMIUM
                        </span>
                    </div>
                </div>
            </div>
            
            <!-- Timed Access Status (hidden initially) -->
            <div id="timed-access-status" class="hidden mb-3 p-2 bg-gradient-to-r from-yellow-500/20 to-orange-500/20 border border-yellow-500/30 rounded-lg">
                <div class="flex items-center justify-center gap-2 text-sm">
                    <i class="fas fa-infinity text-yellow-400"></i>
                    <span class="text-yellow-400 font-bold">UNLIMITED ACCESS</span>
                    <div class="flex items-center gap-1 ml-2">
                        <i class="fas fa-clock text-orange-400 text-xs"></i>
                        <span id="timed-access-countdown" class="font-mono font-bold text-orange-400 bg-black/20 px-2 py-0.5 rounded text-xs">
                            --:--
                        </span>
                    </div>
                </div>
            </div>
            
            <!-- Balance Display -->
            <div class="flex items-center justify-center gap-4 text-sm mb-3">
                <div class="flex items-center gap-1.5">
                    <i class="fas fa-coins text-cyan-400 text-xs"></i>
                    <span class="text-gray-400">Tokens:</span>
                    <span class="font-bold text-cyan-400" id="token-balance">--</span>
                </div>
                <div class="w-px h-4 bg-gray-600"></div>
                <div class="flex items-center gap-1.5">
                    <i class="fas fa-gift text-green-400 text-xs"></i>
                    <span class="text-gray-400">Free:</span>
                    <span class="font-bold text-green-400" id="free-generates">--</span>
                </div>
            </div>
            
            <!-- Purchase Options -->
            <div id="purchase-options" class="space-y-2">
                <p class="text-xs text-gray-400 text-center">Choose payment method:</p>
                <div class="grid grid-cols-3 gap-2">
                    <button 
                        id="buy-permanent-access-btn"
                        class="group bg-gradient-to-r from-emerald-500 to-green-500 hover:from-emerald-600 hover:to-green-600 text-white px-2 py-1 rounded text-xs font-medium transition-all duration-200 hover:scale-105 flex items-center gap-1"
                        title="One-time payment, lifetime unlimited access"
                    >
                        <i class="fas fa-crown text-xs"></i>
                        <span>Lifetime</span>
                    </button>
                    <button 
                        id="buy-timed-access-btn"
                        class="group bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-white px-2 py-1 rounded text-xs font-medium transition-all duration-200 hover:scale-105 flex items-center gap-1"
                        title="Pay for time, unlimited generations"
                    >
                        <i class="fas fa-infinity text-xs"></i>
                        <span>PisoGen</span>
                    </button>
                    <button 
                        id="buy-tokens-btn"
                        class="group bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-2 py-1 rounded text-xs font-medium transition-all duration-200 hover:scale-105 flex items-center gap-1"
                        title="Pay per generation, ₱20 each"
                    >
                        <i class="fas fa-coins text-xs"></i>
                        <span>Tokens</span>
                    </button>
                </div>
            </div>
            
            <!-- Lifetime Access Notice (hidden initially) -->
            <div id="lifetime-access-notice" class="hidden space-y-2">
                <div class="bg-gradient-to-r from-emerald-500/20 to-green-500/20 border border-emerald-500/30 rounded-lg p-3 text-center">
                    <div class="flex items-center justify-center gap-2 mb-2">
                        <i class="fas fa-crown text-emerald-400 text-sm"></i>
                        <span class="text-emerald-400 font-bold text-sm">VIP MEMBER</span>
                        <i class="fas fa-crown text-emerald-400 text-sm"></i>
                    </div>
                    <p class="text-xs text-emerald-300 mb-1">You have lifetime unlimited access!</p>
                    <p class="text-xs text-gray-400">No need to purchase additional access or tokens</p>
                </div>
            </div>
            
            <!-- VIP Redeem Code Section -->
            <div id="vip-redeem-section" class="mt-4">
                <button 
                    id="redeem-toggle-btn"
                    onclick="toggleRedeemSection()"
                    class="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-purple-600/20 to-pink-600/20 hover:from-purple-600/30 hover:to-pink-600/30 border border-purple-500/30 text-purple-300 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200"
                >
                    <i class="fas fa-gift text-xs"></i>
                    <span>Have a VIP Code?</span>
                    <i id="redeem-arrow" class="fas fa-chevron-down text-xs transition-transform duration-200"></i>
                </button>
                
                <div id="redeem-section" class="hidden mt-3 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-lg p-4">
                    <div class="text-center mb-3">
                        <h3 class="text-sm font-semibold text-purple-300 mb-1">
                            <i class="fas fa-star text-yellow-400 mr-1"></i>
                            VIP Code Redemption
                        </h3>
                        <p class="text-xs text-gray-400">Enter your exclusive VIP code below</p>
                    </div>
                    
                    <form id="redeem-code-form" class="space-y-2">
                        <div class="flex gap-2">
                            <input 
                                type="text" 
                                id="redeem-code-input"
                                placeholder="Enter VIP code..."
                                class="flex-1 px-2 py-1.5 bg-gray-900/80 border border-purple-500/30 rounded text-white text-xs focus:outline-none focus:ring-1 focus:ring-purple-400 focus:border-transparent placeholder:text-gray-500 uppercase"
                                maxlength="20"
                                style="letter-spacing: 1px;"
                            >
                            <button 
                                type="submit"
                                id="redeem-btn"
                                class="px-3 py-1.5 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white rounded text-xs font-semibold transition-all duration-200 whitespace-nowrap"
                            >
                                <i class="fas fa-magic mr-1"></i>Redeem
                            </button>
                        </div>
                        
                        <div class="bg-purple-900/20 border border-purple-500/20 rounded p-2">
                            <div class="text-xs text-purple-300 font-medium mb-1">
                                <i class="fas fa-info-circle mr-1"></i>Available Rewards:
                            </div>
                            <div class="text-xs text-gray-300 space-y-0.5">
                                <div>• Free tokens (5-10 tokens)</div>
                                <div>• Timed unlimited access (30 min)</div>
                                <div>• Lifetime premium access</div>
                                <div>• Premium products section unlock</div>
                                <div class="text-yellow-400">• Each user can redeem each code once</div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Free Generate Countdown -->
        <div id="countdown-container" class="max-w-lg mx-auto mb-2 hidden">
            <div class="bg-blue-500/10 border border-cyan-400/20 rounded px-3 py-1.5">
                <div class="flex items-center justify-center gap-2 text-xs">
                    <i class="fas fa-clock text-cyan-400 text-xs"></i>
                    <span class="text-gray-400">Next free:</span>
                    <div id="countdown-timer" class="font-mono font-semibold text-cyan-400 bg-black/20 px-1.5 py-0.5 rounded text-xs">
                        --:--:--
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Original Generator Section (unchanged) -->
        <div class="border border-gray-700/50 bg-black/30 backdrop-blur-sm rounded-lg p-6 md:p-8 text-center max-w-lg mx-auto">
            <h2 class="text-lg sm:text-xl font-bold text-gray-100 tracking-wide mb-2 uppercase">Generate Gift Link</h2>
            <p class="text-xs sm:text-sm text-gray-400 leading-relaxed mb-6">
                Paste your TEMU share link below and we'll generate an optimized gift link that's ready to use. Works with any TEMU product link.
            </p>

            <!-- Auto Processing Status -->
            <div id="auto-status" class="auto-status">
                <span class="text-sm font-medium text-cyan-300" id="auto-status-text" style="white-space: nowrap;">
                    <i class="fas fa-rocket"></i> Processing automatically...
                </span>
            </div>

            <!-- Link Generator Form -->
            <form method="POST" class="w-full max-w-md mx-auto" id="generator-form">
                <div class="flex flex-col gap-3">
                    <input 
                        type="url" 
                        name="share_link"
                        id="share_link"
                        placeholder="https://share.temu.com/..."
                        value="<?php echo isset($_POST['share_link']) ? htmlspecialchars($_POST['share_link']) : ''; ?>"
                        required
                        class="w-full px-4 py-3 text-sm text-gray-200 bg-gray-900/80 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all duration-200 placeholder:text-gray-600"
                    >
                    <button 
                        type="submit"
                        name="extract_link"
                        id="generate-btn"
                        class="w-full px-6 py-3 text-sm font-bold text-gray-900 bg-cyan-400 rounded-md hover:bg-white hover:text-black focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-white transition-all duration-200 whitespace-nowrap"
                    >
                        GENERATE GIFT LINK
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Ad Placement 2: After Main Generator -->
        <div class="max-w-2xl mx-auto my-8">
            <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6401000892288183"
                 crossorigin="anonymous"></script>
            <ins class="adsbygoogle"
                 style="display:block"
                 data-ad-format="fluid"
                 data-ad-layout-key="-fq-t+49-2h-62"
                 data-ad-client="ca-pub-6401000892288183"
                 data-ad-slot="8298915899"></ins>
            <script>
                 (adsbygoogle = window.adsbygoogle || []).push({});
            </script>
        </div>
        
        <!-- All Link Generators Selection Section -->
        <div class="max-w-lg mx-auto mt-8">
            <div class="border border-gray-700/50 bg-black/30 backdrop-blur-sm rounded-lg p-6 text-center">
                <h2 class="text-lg sm:text-xl font-bold text-gray-100 tracking-wide mb-2 uppercase flex items-center justify-center gap-2">
                    <i class="fas fa-link text-purple-400"></i>
                    All Link Generators
                </h2>
                <p class="text-xs sm:text-sm text-gray-400 leading-relaxed mb-6">
                    Access different types of TEMU link generators for various use cases and enhanced features.
                </p>
                
                <div class="space-y-3">
                    <!-- Standard Generator Option -->
                    <div class="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg p-4 hover:from-cyan-500/20 hover:to-blue-500/20 transition-all duration-200 cursor-pointer" onclick="selectGenerator('standard')">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-full flex items-center justify-center">
                                <i class="fas fa-gift text-white"></i>
                            </div>
                            <div class="text-left">
                                <h3 class="text-sm font-bold text-cyan-400">Standard Gift Generator</h3>
                                <p class="text-xs text-gray-400">Original kuiper format • Most compatible</p>
                            </div>
                            <div class="ml-auto">
                                <i class="fas fa-chevron-right text-cyan-400"></i>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Full Return Generator Option -->
                    <div class="bg-gradient-to-r from-purple-600/10 to-pink-600/10 border border-purple-600/30 rounded-lg p-4 hover:from-purple-600/20 hover:to-pink-600/20 transition-all duration-200 cursor-pointer shadow-md hover:shadow-lg" onclick="selectGenerator('full_return')">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-purple-600 to-pink-600 rounded-full flex items-center justify-center shadow-md">
                                <i class="fas fa-sync-alt text-white"></i>
                            </div>
                            <div class="text-left">
                                <h3 class="text-sm font-bold text-purple-300">Full Return Generator</h3>
                                <p class="text-xs text-gray-400">Advanced bgnb format • Enhanced tracking</p>
                            </div>
                            <div class="ml-auto">
                                <i class="fas fa-chevron-right text-purple-300"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Ready-to-Use Products Section -->
        <div class="max-w-lg mx-auto mt-8">
            <div id="premium-section" class="border border-gray-700/50 bg-black/30 backdrop-blur-sm rounded-lg p-6 text-center relative">
                <h2 class="text-lg sm:text-xl font-bold text-gray-100 tracking-wide mb-2 uppercase flex items-center justify-center gap-2">
                    <i class="fas fa-crown text-yellow-400"></i>
                    Ready-to-Use Products
                </h2>
                
                <!-- Locked State -->
                <div id="locked-content" class="blur-sm pointer-events-none">
                    <p class="text-xs sm:text-sm text-gray-400 leading-relaxed mb-6">
                        Premium curated products with instant gift links. Purchase once and access anytime without using tokens.
                    </p>
                    
                    <div class="space-y-4">
                        <div class="bg-gray-900/50 rounded-lg p-4 border border-gray-600/30">
                            <div class="flex items-start justify-between gap-4">
                                <div class="text-left min-w-0 flex-1">
                                    <h3 class="text-xs font-semibold text-gray-200 mb-1 whitespace-nowrap truncate">POCO C61 4+128 GB</h3>
                                    <p class="text-xs text-gray-400 mb-2">Premium Smartphone • High Performance</p>
                                    <div class="flex items-center gap-2">
                                        <span class="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-1 rounded">Premium</span>
                                        <span class="text-xs text-gray-500">Instant Access</span>
                                    </div>
                                </div>
                                <div class="text-right">
                                    <button class="bg-gradient-to-r from-green-500 to-emerald-500 text-white px-4 py-2 rounded-lg text-xs font-semibold">
                                        <i class="fas fa-external-link-alt mr-1"></i>Open Link
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Unlock Button (appears over blurred content) -->
                <div id="unlock-overlay" class="absolute inset-0 flex items-center justify-center bg-black/20 rounded-lg">
                    <div class="bg-black/80 backdrop-blur-md rounded-xl p-6 text-center">
                        <i class="fas fa-lock text-purple-400 text-2xl mb-3"></i>
                        <h3 class="text-lg font-bold text-white mb-2">Unlock Premium Section</h3>
                        <p class="text-sm text-gray-300 mb-4">Get instant access to curated products</p>
                        <div class="text-2xl font-bold text-purple-400 mb-4">₱49</div>
                        <button 
                            onclick="purchasePremiumSection()"
                            class="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-6 py-3 rounded-lg font-semibold transition-all duration-200 hover:scale-105"
                        >
                            <i class="fas fa-crown mr-2"></i>Unlock Section
                        </button>
                    </div>
                </div>
                
                <!-- Unlocked Content (hidden initially) -->
                <div id="unlocked-content" class="hidden">
                    <p class="text-xs sm:text-sm text-gray-400 leading-relaxed mb-6">
                        Premium curated products with instant gift links. Access anytime without using tokens.
                    </p>
                    
                    <div class="space-y-4">
                        <div class="bg-gray-900/50 rounded-lg p-4 border border-gray-600/30">
                            <div class="flex items-start justify-between gap-4">
                                <div class="text-left min-w-0 flex-1">
                                    <h3 class="text-xs font-semibold text-gray-200 mb-1 whitespace-nowrap truncate">POCO C61 4+128 GB</h3>
                                    <p class="text-xs text-gray-400 mb-2">Premium Smartphone • High Performance</p>
                                    <div class="flex items-center gap-2">
                                        <span class="text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded">Unlocked</span>
                                        <span class="text-xs text-gray-500">Instant Access</span>
                                    </div>
                                </div>
                                <div class="text-right">
                                    <button 
                                        onclick="openProductLink('601101201529861', 'POCO C61 4+128 GB')"
                                        class="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 hover:scale-105"
                                    >
                                        <i class="fas fa-external-link-alt mr-1"></i>Open Link
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Ad Placement 3: Before Footer -->
    <div class="max-w-2xl mx-auto my-8 px-4">
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6401000892288183"
             crossorigin="anonymous"></script>
        <ins class="adsbygoogle"
             style="display:block"
             data-ad-format="autorelaxed"
             data-ad-client="ca-pub-6401000892288183"
             data-ad-slot="5942531087"></ins>
        <script>
             (adsbygoogle = window.adsbygoogle || []).push({});
        </script>
    </div>

    <!-- Footer -->
    <footer class="mt-8 bg-black/30 backdrop-blur-md border-t border-gray-700/50 w-screen -mx-4 -mb-4 relative">
        <div class="px-3 py-2 text-center text-xs text-gray-400 space-y-1">
            <div class="whitespace-nowrap">
                <span class="text-cyan-400 font-medium">TEMU Gift Generator</span>
                <span class="mx-2">|</span>
                <span>ALPS</span>
            </div>
            <div class="whitespace-nowrap">
                <span>Developed by</span>
                <span class="text-purple-400 font-semibold tracking-wide mx-1">Joven Campomanes</span>
                <span class="mx-2">•</span>
                <span class="text-cyan-400 font-medium">v1.0</span>
            </div>
        </div>
    </footer>

    <!-- Success Modal -->
    <div id="successModal" class="modal">
        <div class="modal-content success">
            <span class="modal-close" onclick="closeModal('successModal')">&times;</span>
            <i class="fas fa-check-circle modal-icon success"></i>
            <h2 class="modal-title">Gift Link Generated!</h2>
            <p class="modal-message"><?php echo $success ? htmlspecialchars($success) : 'Your TEMU gift link has been created successfully.'; ?></p>
            <?php if ($show_result && $display_goods_id): ?>
            <p class="modal-submessage">Product ID: <?php echo htmlspecialchars($display_goods_id); ?></p>
            <p class="modal-submessage">Generator: <?php echo isset($_POST['generator_type']) && $_POST['generator_type'] === 'full_return' ? 'Full Return Activity' : 'Standard Gift Link'; ?></p>
            <p class="modal-submessage">
                <i class="fas fa-rocket"></i> Opening TEMU app automatically...
            </p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Error Modal -->
    <div id="errorModal" class="modal">
        <div class="modal-content error">
            <span class="modal-close" onclick="closeModal('errorModal')">&times;</span>
            <i class="fas fa-exclamation-triangle modal-icon error"></i>
            <h2 class="modal-title">Generation Failed</h2>
            <p class="modal-message" id="errorMessage">
                <?php echo $error ? htmlspecialchars($error) : ''; ?>
            </p>
            <?php if ($token_error): ?>
            <div class="mt-4">
                                    <button 
                        onclick="closeModal('errorModal'); showModal('buyTokensModal');"
                        class="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200"
                    >
                        <i class="fas fa-plus mr-1"></i>
                        Buy Tokens
                    </button>
            </div>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Premium Purchase Confirmation Modal -->
    <div id="premiumConfirmModal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal('premiumConfirmModal')">&times;</span>
            <div class="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center mx-auto mb-3">
                <i class="fas fa-crown text-white text-lg"></i>
            </div>
            <h2 class="text-lg font-bold text-white mb-2">Unlock Premium Section</h2>
            <p class="text-sm text-gray-300 mb-4">
                Unlock for <strong class="text-purple-400">₱49</strong> - Permanent access to curated products
            </p>
            
            <div class="flex gap-3">
                <button 
                    type="button" 
                    onclick="closeModal('premiumConfirmModal')" 
                    class="flex-1 px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors text-sm"
                >
                    Cancel
                </button>
                <button 
                    type="button" 
                    onclick="confirmPremiumPurchase()"
                    class="flex-1 px-3 py-2 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white rounded-lg font-semibold transition-all duration-200 text-sm"
                >
                    <i class="fas fa-crown mr-1"></i>Unlock
                </button>
            </div>
        </div>
    </div>

    <!-- Buy Timed Access Modal (Piso Wifi Style) -->
    <div id="buyTimedAccessModal" class="modal">
        <div class="modal-content" style="max-width: 320px; padding: 16px;">
            <span class="modal-close" onclick="closeModal('buyTimedAccessModal')" style="top: 8px; right: 12px; font-size: 18px;">&times;</span>
            
            <!-- Compact Header -->
            <div class="text-center mb-3">
                <div class="w-8 h-8 bg-gradient-to-br from-yellow-500 to-orange-500 rounded-full flex items-center justify-center mx-auto mb-1">
                    <i class="fas fa-infinity text-white text-sm"></i>
                </div>
                <h2 class="text-base font-bold text-white mb-0">PisoGen</h2>
                <p class="text-xs text-gray-400">Unlimited • Pay per time</p>
            </div>
            
            <!-- Inline Balance -->
            <div class="flex items-center justify-center gap-2 mb-3 text-xs">
                <i class="fas fa-wallet text-cyan-400"></i>
                <span class="text-gray-400">Balance:</span>
                <span class="font-bold text-cyan-400" id="wallet-balance-timed">₱--</span>
            </div>
            
            <!-- Compact Options -->
            <div class="grid grid-cols-2 gap-2 mb-3">
                <div class="border border-yellow-500/30 rounded p-2 hover:bg-yellow-500/10 transition-colors cursor-pointer text-center" onclick="selectTimedAccess('5min', 5)">
                    <input type="radio" name="timed-access" value="5min" id="access-5min" class="mb-1 accent-yellow-500 scale-75">
                    <div class="text-yellow-400 font-bold">₱5</div>
                    <div class="text-white text-xs">5 min</div>
                    <div class="text-gray-500 text-[10px]">Quick</div>
                </div>
                
                <div class="border border-orange-500/30 rounded p-2 hover:bg-orange-500/10 transition-colors cursor-pointer text-center relative" onclick="selectTimedAccess('15min', 10)">
                    <div class="absolute -top-1 -right-1 bg-orange-500 text-white text-[8px] px-1 rounded font-bold">BEST</div>
                    <input type="radio" name="timed-access" value="15min" id="access-15min" class="mb-1 accent-orange-500 scale-75">
                    <div class="text-orange-400 font-bold">₱10</div>
                    <div class="text-white text-xs">15 min</div>
                    <div class="text-gray-500 text-[10px]">Value</div>
                </div>
            </div>
            
            <!-- Selection Summary -->
            <div id="selected-access-info" class="hidden bg-yellow-500/10 border border-yellow-500/30 rounded p-2 mb-3">
                <div class="flex justify-between items-center text-sm">
                    <span class="text-gray-300" id="selected-access-text">--</span>
                    <span class="font-bold" id="selected-access-cost">₱--</span>
                </div>
            </div>
            
            <!-- Action Buttons -->
            <div class="flex gap-2">
                <button 
                    type="button" 
                    onclick="closeModal('buyTimedAccessModal')" 
                    class="flex-1 px-3 py-1.5 bg-gray-600/80 hover:bg-gray-600 text-white rounded text-xs transition-colors"
                >
                    Cancel
                </button>
                <button 
                    type="button"
                    id="purchase-timed-access-btn"
                    onclick="handleTimedAccessPurchase()"
                    disabled
                    class="flex-1 px-3 py-1.5 bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-white rounded text-xs font-semibold transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    <i class="fas fa-infinity text-xs mr-1"></i>Activate
                </button>
            </div>
        </div>
    </div>

    <!-- Buy Tokens Modal -->
    <div id="buyTokensModal" class="modal">
        <div class="modal-content" style="max-width: 300px; padding: 16px;">
            <span class="modal-close" onclick="closeModal('buyTokensModal')" style="top: 8px; right: 12px; font-size: 18px;">&times;</span>
            
            <!-- Compact Header -->
            <div class="text-center mb-3">
                <div class="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center mx-auto mb-1">
                    <i class="fas fa-coins text-white text-sm"></i>
                </div>
                <h2 class="text-base font-bold text-white mb-0">Buy Tokens</h2>
                <p class="text-xs text-gray-400">₱20 per token • Pay per use</p>
            </div>
            
            <!-- Inline Balance -->
            <div class="flex items-center justify-center gap-2 mb-3 text-xs">
                <i class="fas fa-wallet text-cyan-400"></i>
                <span class="text-gray-400">Balance:</span>
                <span class="font-bold text-cyan-400" id="wallet-balance">₱--</span>
            </div>
            
            <form id="buy-tokens-form" class="space-y-3">
                <!-- Quantity Input -->
                <div class="flex items-center gap-2">
                    <label class="text-xs text-gray-300 whitespace-nowrap">Tokens:</label>
                    <input 
                        type="number" 
                        id="token-quantity" 
                        min="1" 
                        max="100" 
                        value="1" 
                        class="flex-1 px-2 py-1 bg-gray-900/80 border border-gray-600 rounded text-white focus:outline-none focus:ring-1 focus:ring-purple-500 text-sm"
                    >
                    <span class="text-xs text-gray-400">x ₱20</span>
                </div>
                
                <!-- Total Cost -->
                <div class="bg-purple-500/10 border border-purple-500/20 rounded p-2">
                    <div class="flex justify-between items-center">
                        <span class="text-xs text-gray-300">Total:</span>
                        <span class="font-bold text-purple-400" id="total-cost">₱20.00</span>
                    </div>
                </div>
                
                <!-- Action Buttons -->
                <div class="flex gap-2">
                    <button 
                        type="button" 
                        onclick="closeModal('buyTokensModal')" 
                        class="flex-1 px-3 py-1.5 bg-gray-600/80 hover:bg-gray-600 text-white rounded text-xs transition-colors"
                    >
                        Cancel
                    </button>
                    <button 
                        type="submit" 
                        class="flex-1 px-3 py-1.5 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white rounded text-xs font-semibold transition-all duration-200"
                    >
                        <i class="fas fa-coins text-xs mr-1"></i>Purchase
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Buy Permanent Access Modal -->
    <div id="buyPermanentAccessModal" class="modal">
        <div class="modal-content" style="max-width: 320px; padding: 16px;">
            <span class="modal-close" onclick="closeModal('buyPermanentAccessModal')" style="top: 8px; right: 12px; font-size: 18px;">&times;</span>
            
            <!-- Header -->
            <div class="text-center mb-3">
                <div class="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-full flex items-center justify-center mx-auto mb-1">
                    <i class="fas fa-crown text-white text-sm"></i>
                </div>
                <h2 class="text-base font-bold text-white mb-0">Lifetime Unlimited</h2>
                <p class="text-xs text-gray-400">One-time payment • Forever access</p>
            </div>
            
            <!-- Balance -->
            <div class="flex items-center justify-center gap-2 mb-3 text-xs">
                <i class="fas fa-wallet text-cyan-400"></i>
                <span class="text-gray-400">Balance:</span>
                <span class="font-bold text-cyan-400" id="wallet-balance-permanent">₱--</span>
            </div>
            
            <!-- Pricing Card -->
            <div class="bg-gradient-to-br from-emerald-500/20 to-green-500/20 border border-emerald-500/30 rounded-lg p-3 mb-3 text-center">
                <div class="mb-2">
                    <div class="text-emerald-400 text-xl font-bold">₱299</div>
                    <div class="text-green-400 text-xs font-medium">One-time payment</div>
                </div>
                
                <div class="space-y-0.5 text-xs">
                    <div class="flex items-center justify-center gap-1 text-white">
                        <i class="fas fa-check text-emerald-400 text-xs"></i>
                        <span>Unlimited generations forever</span>
                    </div>
                    <div class="flex items-center justify-center gap-1 text-white">
                        <i class="fas fa-check text-emerald-400 text-xs"></i>
                        <span>No time limits or expiry</span>
                    </div>
                    <div class="flex items-center justify-center gap-1 text-white">
                        <i class="fas fa-check text-emerald-400 text-xs"></i>
                        <span>Premium member status</span>
                    </div>
                </div>
                
                <div class="mt-2 p-1.5 bg-emerald-500/10 rounded border border-emerald-500/20">
                    <div class="text-emerald-400 text-xs font-bold">💡 BEST VALUE</div>
                    <div class="text-gray-300 text-[10px]">Equals 15 tokens value!</div>
                </div>
            </div>
            
            <!-- Action Buttons -->
            <div class="flex gap-2">
                <button 
                    type="button" 
                    onclick="closeModal('buyPermanentAccessModal')" 
                    class="flex-1 px-3 py-1.5 bg-gray-600/80 hover:bg-gray-600 text-white rounded text-xs transition-colors"
                >
                    Cancel
                </button>
                <button 
                    type="button"
                    id="purchase-permanent-access-btn"
                    onclick="handlePermanentAccessPurchase()"
                    class="flex-1 px-3 py-1.5 bg-gradient-to-r from-emerald-500 to-green-500 hover:from-emerald-600 hover:to-green-600 text-white rounded text-xs font-bold transition-all duration-200"
                >
                    <i class="fas fa-crown text-xs mr-1"></i>Get Lifetime
                </button>
            </div>
        </div>
    </div>

    <!-- Generator Selection Modal -->
    <div id="generatorModal" class="modal">
        <div class="modal-content" style="max-width: 400px;">
            <span class="modal-close" onclick="closeModal('generatorModal')">&times;</span>
            <div class="text-center">
                <div id="selected-generator-icon" class="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-gift text-white text-xl"></i>
                </div>
                <h2 id="selected-generator-title" class="text-xl font-bold text-white mb-2">Standard Gift Generator</h2>
                <p id="selected-generator-description" class="text-sm text-gray-300 mb-6">Creates standard TEMU gift links with optimized parameters for maximum compatibility.</p>
                
                <!-- Generator Form -->
                <form method="POST" id="selected-generator-form">
                    <input type="hidden" id="selected-generator-type" name="generator_type" value="standard">
                    <div class="space-y-3">
                        <input 
                            type="url" 
                            name="share_link"
                            id="selected-share-link"
                            placeholder="https://share.temu.com/..."
                            required
                            class="w-full px-4 py-3 text-sm text-gray-200 bg-gray-900/80 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all duration-200 placeholder:text-gray-600"
                        >
                        <button 
                            type="submit"
                            name="extract_link"
                            id="selected-generate-btn"
                            class="w-full px-6 py-3 text-sm font-bold text-gray-900 bg-cyan-400 rounded-md hover:bg-white hover:text-black focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-white transition-all duration-200"
                        >
                            GENERATE STANDARD LINK
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Chat Toggle Button -->
    <button id="chat-toggle-btn" onclick="toggleChat()">
        <i class="fas fa-comments"></i>
    </button>

    <!-- Full Page Chat Modal -->
    <div id="full-chat-modal">
        <div class="chat-container">
            <!-- Chat Sidebar -->
            <div class="chat-sidebar">
                <div class="sidebar-section">
                    <div class="sidebar-title">
                        <i class="fas fa-users"></i> Online (<span id="online-count">0</span>)
                    </div>
                    <div class="online-users" id="online-users">
                        <!-- Online users will be loaded here -->
                    </div>
                </div>
                <div class="sidebar-section">
                    <div class="sidebar-title">
                        <i class="fas fa-chart-line"></i> Your Stats
                    </div>
                    <div style="font-size: 10px; color: #ccc;">
                        <div>Tokens sent today: <span id="tokens-sent-today">--</span>/10</div>
                        <div>Messages sent: <span id="messages-sent">--</span></div>
                    </div>
                </div>
            </div>

            <!-- Chat Main Area -->
            <div class="chat-main">
                <div class="chat-header">
                    <h4><i class="fas fa-comments mr-2"></i>Community Chat</h4>
                    <button class="chat-close-btn" onclick="toggleChat()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="chat-content">
                    <div class="chat-messages" id="chat-messages">
                        <!-- Messages will be loaded here -->
                    </div>
                    <div id="typing-indicators"></div>
                    <div class="chat-input-area">
                        <div class="chat-options">
                            <button class="chat-option-btn active" onclick="setChatMode('chat')">💬 Chat</button>
                            <button class="chat-option-btn" onclick="setChatMode('transfer')">🪙 Send Tokens</button>
                            <button class="chat-option-btn" onclick="toggleEmojiPicker()">😀 Emojis</button>
                        </div>
                        <div class="chat-input-container">
                            <div class="input-wrapper">
                                <input type="text" id="chat-input" placeholder="Type a message..." maxlength="200">
                                <button class="emoji-toggle-btn" onclick="toggleEmojiPicker()">😀</button>
                                <div class="emoji-picker" id="emoji-picker">
                                    <div class="emoji-grid">
                                        <button class="emoji-btn" onclick="insertEmoji('😀')">😀</button>
                                        <button class="emoji-btn" onclick="insertEmoji('😂')">😂</button>
                                        <button class="emoji-btn" onclick="insertEmoji('😍')">😍</button>
                                        <button class="emoji-btn" onclick="insertEmoji('🤔')">🤔</button>
                                        <button class="emoji-btn" onclick="insertEmoji('👍')">👍</button>
                                        <button class="emoji-btn" onclick="insertEmoji('👎')">👎</button>
                                        <button class="emoji-btn" onclick="insertEmoji('❤️')">❤️</button>
                                        <button class="emoji-btn" onclick="insertEmoji('🔥')">🔥</button>
                                        <button class="emoji-btn" onclick="insertEmoji('💯')">💯</button>
                                        <button class="emoji-btn" onclick="insertEmoji('🎉')">🎉</button>
                                        <button class="emoji-btn" onclick="insertEmoji('🚀')">🚀</button>
                                        <button class="emoji-btn" onclick="insertEmoji('⚡')">⚡</button>
                                    </div>
                                </div>
                            </div>
                            <button class="chat-send-btn" onclick="sendMessage()">Send</button>
                        </div>
                        <div class="token-transfer-controls" id="token-transfer-controls">
                            <div class="transfer-input-group">
                                <input type="text" id="target-username" placeholder="Username" style="flex: 2;">
                                <input type="number" id="token-amount" placeholder="Tokens" min="1" max="10" style="flex: 1;">
                            </div>
                            <div class="transfer-info" id="transfer-info">Daily limit: 10 tokens</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
    // Cyberpunk Preloader JavaScript
    document.addEventListener('DOMContentLoaded', function() {
        initCyberpunkPreloader();
    });

    function initCyberpunkPreloader() {
        createEnhancedParticles();
        updateEnhancedStatusText();
        
        // Hide preloader when everything is loaded
        window.addEventListener('load', function() {
            setTimeout(hidePreloader, 1200); // Wait 1.2 seconds after load
        });
    }

    function createEnhancedParticles() {
        const particleContainer = document.getElementById('cyber-particles');
        const particleCount = Math.min(50, Math.floor(window.innerWidth / 30));
        
        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'cyber-particle';
            
            // Randomly assign pink or cyan particles
            if (Math.random() > 0.6) {
                particle.classList.add('pink');
            }
            
            // Random positioning and timing
            particle.style.left = Math.random() * 100 + '%';
            particle.style.animationDuration = (Math.random() * 4 + 3) + 's';
            particle.style.animationDelay = Math.random() * 2 + 's';
            
            // Random size variation
            const size = Math.random() * 2 + 1;
            particle.style.width = size + 'px';
            particle.style.height = size + 'px';
            
            particleContainer.appendChild(particle);
        }
    }

    function updateEnhancedStatusText() {
        const statusElement = document.getElementById('cyber-status');
        const messages = [
            'INITIALIZING SYSTEM...',
            'LOADING NEURAL NETWORKS...',
            'CONNECTING TO MAINFRAME...',
            'SCANNING QUANTUM CHANNELS...',
            'ESTABLISHING SECURE CONNECTION...',
            'ACTIVATING CYBER PROTOCOLS...',
            'CALIBRATING AI MATRICES...',
            'SYNCHRONIZING DATA STREAMS...',
            'BOOTING ADVANCED SYSTEMS...',
            'READY TO GENERATE...'
        ];
        
        let messageIndex = 0;
        
        const updateMessage = () => {
            // Add typing effect
            statusElement.style.opacity = '0.3';
            setTimeout(() => {
                statusElement.textContent = messages[messageIndex];
                statusElement.style.opacity = '1';
                messageIndex++;
                
                if (messageIndex < messages.length) {
                    setTimeout(updateMessage, 350);
                }
            }, 100);
        };
        
        updateMessage();
    }

    function hidePreloader() {
        const preloader = document.getElementById('cyberpunk-preloader');
        preloader.classList.add('preloader-hidden');
        
        // Remove from DOM after transition
        setTimeout(() => {
            preloader.remove();
        }, 500);
    }

    // Original particle canvas code
    const canvas = document.getElementById('particle-canvas');
    const ctx = canvas.getContext('2d');

    let particlesArray;

    // Mouse position
    const mouse = {
        x: null,
        y: null,
        radius: (canvas.height / 100) * (canvas.width / 100)
    }

    window.addEventListener('mousemove', 
        function(event) {
            mouse.x = event.x;
            mouse.y = event.y;
        }
    );
    window.addEventListener('mouseout', 
        function() {
            mouse.x = null;
            mouse.y = null;
        }
    );

    // Particle class
    class Particle {
        constructor(x, y, directionX, directionY, size, color) {
            this.x = x;
            this.y = y;
            this.directionX = directionX;
            this.directionY = directionY;
            this.size = size;
            this.color = color;
        }

        // Method to draw individual particle
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2, false);
            ctx.fillStyle = this.color;
            ctx.fill();
        }

        // Check particle position, check mouse position, move the particle, draw the particle
        update() {
            // Check if particle is still within canvas
            if (this.x > canvas.width || this.x < 0) {
                this.directionX = -this.directionX;
            }
            if (this.y > canvas.height || this.y < 0) {
                this.directionY = -this.directionY;
            }

            // Move particle
            this.x += this.directionX;
            this.y += this.directionY;
            
            // Draw particle
            this.draw();
        }
    }

    // Create particle array
    function init() {
        particlesArray = [];
        // Adjusted particle density for mobile
        let numberOfParticles = Math.max(75, (canvas.height * canvas.width) / 20000);
        for (let i = 0; i < numberOfParticles; i++) {
            let size = (Math.random() * 2) + 1;
            let x = (Math.random() * ((innerWidth - size * 2) - (size * 2)) + size * 2);
            let y = (Math.random() * ((innerHeight - size * 2) - (size * 2)) + size * 2);
            let directionX = (Math.random() * .4) - 0.2;
            let directionY = (Math.random() * .4) - 0.2;
            let color = 'rgba(0, 255, 249, 0.4)';

            particlesArray.push(new Particle(x, y, directionX, directionY, size, color));
        }
    }

    // Animation loop
    function animate() {
        requestAnimationFrame(animate);
        ctx.clearRect(0, 0, innerWidth, innerHeight);

        for (let i = 0; i < particlesArray.length; i++) {
            particlesArray[i].update();
        }
        connect();
    }

    // Check if particles are close enough to draw line between them
    function connect() {
        let opacityValue = 1;
        let connectDistance = (canvas.width / 7) * (canvas.height / 7);

        for (let a = 0; a < particlesArray.length; a++) {
            for (let b = a; b < particlesArray.length; b++) {
                let distance = ((particlesArray[a].x - particlesArray[b].x) * (particlesArray[a].x - particlesArray[b].x)) +
                               ((particlesArray[a].y - particlesArray[b].y) * (particlesArray[a].y - particlesArray[b].y));
                
                if (distance < connectDistance) {
                    // Correctly calculate opacity based on distance
                    opacityValue = 1 - (distance / connectDistance);
                    ctx.strokeStyle = `rgba(0, 255, 249, ${opacityValue})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(particlesArray[a].x, particlesArray[a].y);
                    ctx.lineTo(particlesArray[b].x, particlesArray[b].y);
                    ctx.stroke();
                }
            }
        }
        // Connect to mouse
        if (mouse.x !== null && mouse.y !== null) {
            for (let i = 0; i < particlesArray.length; i++) {
                let distance = ((mouse.x - particlesArray[i].x) * (mouse.x - particlesArray[i].x)) +
                               ((mouse.y - particlesArray[i].y) * (mouse.y - particlesArray[i].y));
                if (distance < mouse.radius) {
                    opacityValue = 1 - (distance / mouse.radius);
                    ctx.strokeStyle = `rgba(0, 255, 249, ${opacityValue})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(mouse.x, mouse.y);
                    ctx.lineTo(particlesArray[i].x, particlesArray[i].y);
                    ctx.stroke();
                }
            }
        }
    }

    // Resize event
    window.addEventListener('resize', 
        function() {
            canvas.width = innerWidth;
            canvas.height = innerHeight;
            mouse.radius = (canvas.height / 100) * (canvas.width / 100);
            init();
        }
    );
    
    // Set initial canvas size
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    init();
    animate();

    // Modal Functions
    function showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
        }
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = 'auto';
        }
    }

    // Close modal when clicking outside of it
    window.onclick = function(event) {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (event.target === modal) {
                modal.classList.remove('show');
                document.body.style.overflow = 'auto';
            }
        });
    }

    // Secure redirect function for TEMU app
    window.redirectToGift = function() {
        // Check if we're already in a redirect to prevent infinite loops
        if (window.location.search.includes('secure_redirect=1')) {
            return;
        }
        
        const currentUrl = new URL(window.location.href);
        currentUrl.searchParams.set('secure_redirect', '1');
        
        // For mobile devices, try to force open the app
        if (isMobileDevice()) {
            window.open(currentUrl.toString(), '_self');
        } else {
            window.location.href = currentUrl.toString();
        }
    };
    
    // Mobile device detection function
    function isMobileDevice() {
        const userAgent = navigator.userAgent || navigator.vendor || window.opera;
        return /android|avantgo|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino/i.test(userAgent) || /1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i.test(userAgent.substr(0,4));
    }

    // Background Music System
    let backgroundAudio = null;
    let isPlaying = false;
    let hasUserInteracted = false;

    function initBackgroundMusic() {
        backgroundAudio = new Audio();
        backgroundAudio.loop = true;
        backgroundAudio.volume = 0.3;
        backgroundAudio.preload = 'metadata'; // Start with metadata only for faster loading
        backgroundAudio.crossOrigin = 'anonymous'; // Enable CORS for better loading
        
        // Enhanced buffering management
        backgroundAudio.addEventListener('loadstart', () => {
            updateMusicStatus('Connecting...');
        });
        
        backgroundAudio.addEventListener('loadedmetadata', () => {
            updateMusicStatus('Loading...');
        });
        
        backgroundAudio.addEventListener('canplay', () => {
            updateMusicStatus('Ready');
        });
        
        backgroundAudio.addEventListener('canplaythrough', () => {
            updateMusicStatus('');
        });
        
        backgroundAudio.addEventListener('waiting', () => {
            updateMusicStatus('Buffering...');
        });
        
        backgroundAudio.addEventListener('playing', () => {
            updateMusicStatus('');
        });
        
        backgroundAudio.addEventListener('stalled', () => {
            updateMusicStatus('Network issue...');
            // Retry loading after a brief pause
            setTimeout(() => {
                if (backgroundAudio.networkState === backgroundAudio.NETWORK_LOADING) {
                    backgroundAudio.load();
                }
            }, 2000);
        });
        
        backgroundAudio.addEventListener('suspend', () => {
            updateMusicStatus('Paused loading');
        });
        
        backgroundAudio.addEventListener('error', (e) => {
            updateMusicStatus('Connection failed');
            console.log('Audio error:', e);
            // Try to reload after error
            setTimeout(() => {
                retryAudioLoad();
            }, 3000);
        });
        
        backgroundAudio.addEventListener('progress', () => {
            if (backgroundAudio.buffered.length > 0) {
                const bufferedEnd = backgroundAudio.buffered.end(backgroundAudio.buffered.length - 1);
                const duration = backgroundAudio.duration;
                if (duration > 0) {
                    const bufferedPercent = (bufferedEnd / duration) * 100;
                    if (bufferedPercent < 100) {
                        updateMusicStatus(`Buffering ${Math.round(bufferedPercent)}%`);
                    }
                }
            }
        });
        
        // Load default track with optimization
        loadTrackOptimized('https://archive.org/download/losing_202508/fainted.mp3');
        
        // Add event listeners for audio management
        addAudioEventListeners();
        
        // Setup event listeners
        setupMusicControls();
    }
    
    function loadTrackOptimized(url) {
        // Clear any existing source
        backgroundAudio.src = '';
        backgroundAudio.load();
        
        // Set new source and load
        backgroundAudio.src = url;
        backgroundAudio.load();
        
        // Try to preload a small portion
        backgroundAudio.addEventListener('loadedmetadata', function preloadHandler() {
            backgroundAudio.removeEventListener('loadedmetadata', preloadHandler);
            // Start loading more data
            backgroundAudio.preload = 'auto';
        }, { once: true });
    }
    
    function retryAudioLoad() {
        if (backgroundAudio && backgroundAudio.src) {
            updateMusicStatus('Retrying...');
            backgroundAudio.load();
        }
    }

    function setupMusicControls() {
        const musicToggle = document.getElementById('music-toggle');
        const musicIcon = document.getElementById('music-icon');
        const trackSelector = document.getElementById('track-selector');
        const volumeSlider = document.getElementById('volume-slider');

        // Play/Pause toggle with better buffering handling
        musicToggle.addEventListener('click', function() {
            if (!hasUserInteracted) {
                hasUserInteracted = true;
                if (backgroundAudio) {
                    backgroundAudio.muted = false;
                }
            }
            
            if (isPlaying) {
                pauseMusic();
            } else {
                playMusicOptimized();
            }
        });

        // Track selection with buffering optimization
        trackSelector.addEventListener('change', function() {
            const newTrack = this.value;
            changeTrackOptimized(newTrack);
        });

        // Volume control
        volumeSlider.addEventListener('input', function() {
            if (backgroundAudio) {
                backgroundAudio.volume = this.value / 100;
            }
        });

        // Auto-unmute on any user interaction
        document.addEventListener('click', function() {
            if (!hasUserInteracted && backgroundAudio) {
                hasUserInteracted = true;
                backgroundAudio.muted = false;
                if (!isPlaying) {
                    playMusicOptimized();
                }
            }
        }, { once: true });
    }

    function playMusicOptimized() {
        if (!backgroundAudio) return;
        
        // Check if enough audio is buffered before playing
        if (backgroundAudio.readyState >= 2) { // HAVE_CURRENT_DATA
            backgroundAudio.play().then(() => {
                isPlaying = true;
                updateMusicIcon();
            }).catch(e => {
                console.log('Playback failed:', e);
                updateMusicStatus('Playback failed');
                // Try again after a short delay
                setTimeout(() => {
                    if (backgroundAudio.readyState >= 2) {
                        backgroundAudio.play().catch(() => {});
                    }
                }, 1000);
            });
        } else {
            // Wait for enough data to be buffered
            updateMusicStatus('Buffering...');
            const onCanPlay = () => {
                backgroundAudio.removeEventListener('canplay', onCanPlay);
                backgroundAudio.play().then(() => {
                    isPlaying = true;
                    updateMusicIcon();
                }).catch(e => {
                    console.log('Delayed playback failed:', e);
                });
            };
            backgroundAudio.addEventListener('canplay', onCanPlay);
        }
    }

    function pauseMusic() {
        if (backgroundAudio) {
            backgroundAudio.pause();
            isPlaying = false;
            updateMusicIcon();
        }
    }

    function changeTrackOptimized(newTrackUrl) {
        const wasPlaying = isPlaying;
        const currentVolume = backgroundAudio ? backgroundAudio.volume : 0.3;
        
        // Pause current track
        if (backgroundAudio) {
            backgroundAudio.pause();
            isPlaying = false;
            updateMusicIcon();
        }
        
        // Update status
        updateMusicStatus('Switching track...');
        
        // Load new track with optimization
        loadTrackOptimized(newTrackUrl);
        
        // Restore volume
        backgroundAudio.volume = currentVolume;
        backgroundAudio.muted = !hasUserInteracted;
        
        // Re-add all event listeners for the new track
        addAudioEventListeners();
        
        // Resume playback if it was playing before
        if (wasPlaying) {
            // Wait a bit for the track to start loading
            setTimeout(() => {
                playMusicOptimized();
            }, 500);
        }
    }
    
    function addAudioEventListeners() {
        if (!backgroundAudio) return;
        
        // Remove any existing listeners to prevent duplicates
        backgroundAudio.removeEventListener('loadstart', handleLoadStart);
        backgroundAudio.removeEventListener('loadedmetadata', handleLoadedMetadata);
        backgroundAudio.removeEventListener('canplay', handleCanPlay);
        backgroundAudio.removeEventListener('canplaythrough', handleCanPlayThrough);
        backgroundAudio.removeEventListener('waiting', handleWaiting);
        backgroundAudio.removeEventListener('playing', handlePlaying);
        backgroundAudio.removeEventListener('stalled', handleStalled);
        backgroundAudio.removeEventListener('suspend', handleSuspend);
        backgroundAudio.removeEventListener('error', handleError);
        backgroundAudio.removeEventListener('progress', handleProgress);
        
        // Add fresh listeners
        backgroundAudio.addEventListener('loadstart', handleLoadStart);
        backgroundAudio.addEventListener('loadedmetadata', handleLoadedMetadata);
        backgroundAudio.addEventListener('canplay', handleCanPlay);
        backgroundAudio.addEventListener('canplaythrough', handleCanPlayThrough);
        backgroundAudio.addEventListener('waiting', handleWaiting);
        backgroundAudio.addEventListener('playing', handlePlaying);
        backgroundAudio.addEventListener('stalled', handleStalled);
        backgroundAudio.addEventListener('suspend', handleSuspend);
        backgroundAudio.addEventListener('error', handleError);
        backgroundAudio.addEventListener('progress', handleProgress);
    }
    
    // Event handler functions
    function handleLoadStart() { updateMusicStatus('Connecting...'); }
    function handleLoadedMetadata() { updateMusicStatus('Loading...'); }
    function handleCanPlay() { updateMusicStatus('Ready'); }
    function handleCanPlayThrough() { updateMusicStatus(''); }
    function handleWaiting() { updateMusicStatus('Buffering...'); }
    function handlePlaying() { updateMusicStatus(''); }
    function handleSuspend() { updateMusicStatus('Paused loading'); }
    
    function handleStalled() {
        updateMusicStatus('Network issue...');
        setTimeout(() => {
            if (backgroundAudio && backgroundAudio.networkState === backgroundAudio.NETWORK_LOADING) {
                backgroundAudio.load();
            }
        }, 2000);
    }
    
    function handleError(e) {
        updateMusicStatus('Connection failed');
        console.log('Audio error:', e);
        setTimeout(() => {
            retryAudioLoad();
        }, 3000);
    }
    
    function handleProgress() {
        if (backgroundAudio && backgroundAudio.buffered.length > 0) {
            const bufferedEnd = backgroundAudio.buffered.end(backgroundAudio.buffered.length - 1);
            const duration = backgroundAudio.duration;
            if (duration > 0) {
                const bufferedPercent = (bufferedEnd / duration) * 100;
                if (bufferedPercent < 100) {
                    updateMusicStatus(`Buffering ${Math.round(bufferedPercent)}%`);
                }
            }
        }
    }

    function updateMusicStatus(status) {
        const statusIcon = document.getElementById('music-status-icon');
        const statusText = document.getElementById('music-status-text');
        const trackSelector = document.getElementById('track-selector');
        
        switch(status) {
            case 'Loading...':
                statusIcon.className = 'fas fa-spinner fa-spin text-yellow-400 text-xs';
                statusText.textContent = '';
                statusText.className = 'text-xs text-gray-500 whitespace-nowrap';
                trackSelector.style.pointerEvents = 'none';
                break;
                
            case 'Buffering...':
                statusIcon.className = 'fas fa-circle-notch fa-spin text-orange-400 text-xs';
                statusText.textContent = '';
                statusText.className = 'text-xs text-gray-500 whitespace-nowrap';
                trackSelector.style.pointerEvents = 'none';
                break;
                
            case 'Ready':
                statusIcon.className = 'fas fa-music text-purple-400 text-xs';
                statusText.textContent = '';
                statusText.className = 'text-xs text-gray-500 whitespace-nowrap';
                trackSelector.style.pointerEvents = 'auto';
                break;
                
            case 'Error':
                statusIcon.className = 'fas fa-exclamation-triangle text-red-400 text-xs';
                statusText.textContent = '';
                statusText.className = 'text-xs text-red-400 whitespace-nowrap';
                trackSelector.style.pointerEvents = 'auto';
                break;
                
            default:
                statusIcon.className = 'fas fa-music text-purple-400 text-xs';
                statusText.textContent = '';
                statusText.className = 'text-xs text-gray-500 whitespace-nowrap';
                trackSelector.style.pointerEvents = 'auto';
        }
    }

    function updateMusicIcon() {
        const musicIcon = document.getElementById('music-icon');
        const musicToggle = document.getElementById('music-toggle');
        
        if (isPlaying) {
            musicIcon.className = 'fas fa-pause text-purple-400 text-xs';
            musicToggle.className = 'w-8 h-8 bg-purple-500/30 hover:bg-purple-500/40 rounded-full flex items-center justify-center transition-colors';
        } else {
            musicIcon.className = 'fas fa-play text-purple-400 text-xs';
            musicToggle.className = 'w-8 h-8 bg-purple-500/20 hover:bg-purple-500/30 rounded-full flex items-center justify-center transition-colors';
        }
    }

    // Automatic clipboard detection and processing
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize background music
        initBackgroundMusic();
        
        // Load token balance
        loadTokenBalance();
        
        // Initialize chat system
        initChatSystem();
        
        // Try automatic clipboard detection after page loads
        setTimeout(checkClipboardAutomatically, 1000);
        
        // Form submission handling with animation
        const form = document.getElementById('generator-form');
        const generateBtn = document.getElementById('generate-btn');
        
        if (form) {
            form.addEventListener('submit', function(e) {
                // Show loading animation
                showLoadingAnimation();
            });
        }
        
        // Buy permanent access button (Lifetime)
        const buyPermanentAccessBtn = document.getElementById('buy-permanent-access-btn');
        if (buyPermanentAccessBtn) {
            buyPermanentAccessBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                loadWalletBalance();
                showModal('buyPermanentAccessModal');
            });
        }

        // Buy timed access button (Piso WiFi)
        const buyTimedAccessBtn = document.getElementById('buy-timed-access-btn');
        if (buyTimedAccessBtn) {
            buyTimedAccessBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                loadWalletBalance();
                // Reset any previous selection
                selectedTimedAccess = null;
                document.getElementById('selected-access-info').classList.add('hidden');
                document.getElementById('purchase-timed-access-btn').disabled = true;
                // Clear radio buttons
                document.getElementById('access-5min').checked = false;
                document.getElementById('access-15min').checked = false;
                
                showModal('buyTimedAccessModal');
            });
        }

        // Buy tokens button
        const buyTokensBtn = document.getElementById('buy-tokens-btn');
        if (buyTokensBtn) {
            buyTokensBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                loadWalletBalance();
                // Reset token quantity to 1
                document.getElementById('token-quantity').value = 1;
                updateTotalCost();
                
                showModal('buyTokensModal');
            });
        }
        
        // Token quantity change handler
        const tokenQuantity = document.getElementById('token-quantity');
        if (tokenQuantity) {
            tokenQuantity.addEventListener('input', updateTotalCost);
        }
        
        // Buy tokens form submission
        const buyTokensForm = document.getElementById('buy-tokens-form');
        if (buyTokensForm) {
            buyTokensForm.addEventListener('submit', handleTokenPurchase);
        }
        
        // Redeem code form submission
        const redeemCodeForm = document.getElementById('redeem-code-form');
        if (redeemCodeForm) {
            redeemCodeForm.addEventListener('submit', handleRedeemCode);
        }
        
        // Auto uppercase for redeem code input
        const redeemCodeInput = document.getElementById('redeem-code-input');
        if (redeemCodeInput) {
            redeemCodeInput.addEventListener('input', function() {
                this.value = this.value.toUpperCase();
            });
        }
        
        // Initialize modal generator form
        const modalForm = document.getElementById('selected-generator-form');
        if (modalForm) {
            modalForm.addEventListener('submit', function(e) {
                // Get generator type to determine theme
                const generatorType = document.getElementById('selected-generator-type').value;
                const theme = generatorType === 'full_return' ? 'full-return' : 'standard';
                const text = generatorType === 'full_return' ? 'GENERATING RETURN' : 'GENERATING STANDARD';
                
                // Show loading animation with appropriate theme
                showLoadingAnimation('selected-generate-btn', theme, text);
            });
        }
    });

    // Automatic clipboard detection and processing
    async function checkClipboardAutomatically() {
        // Prevent multiple clipboard checks
        if (window.clipboardChecked) {
            return;
        }
        window.clipboardChecked = true;
        
        if (!navigator.clipboard) {
            return;
        }
        
        try {
            const text = await navigator.clipboard.readText();
            if (text && text.length > 10 && text.includes('temu.com')) {
                const urlInput = document.getElementById('share_link');
                const statusDiv = document.getElementById('auto-status');
                const statusText = document.getElementById('auto-status-text');
                
                // Check if input already has this value to prevent redundant updates
                if (urlInput && urlInput.value !== text.trim()) {
                    // Show detection status
                    if (statusDiv && statusText) {
                        statusText.innerHTML = '<i class="fas fa-clipboard"></i> Link detected from clipboard';
                        statusDiv.classList.add('show');
                    }
                    
                    // Fill the input field
                    urlInput.value = text.trim();
                    urlInput.style.borderColor = '#10b981';
                    urlInput.style.boxShadow = '0 0 0 2px rgba(16, 185, 129, 0.3)';
                    
                    // Wait a moment for user to see the detection
                    setTimeout(() => {
                        // Update status to ready
                        if (statusText) {
                            statusText.innerHTML = '<i class="fas fa-check"></i> Link ready';
                        }
                    }, 1500);
                }
            }
        } catch (err) {
            // Silently fail if clipboard access denied
        }
    }

    function showLoadingAnimation(buttonId = 'generate-btn', theme = 'standard', text = 'GENERATING') {
        const generateBtn = document.getElementById(buttonId);
        if (generateBtn) {
            generateBtn.classList.add('btn-loading', theme);
            generateBtn.innerHTML = `
                <div class="loading-circuit"></div>
                <span class="loading-text">${text}</span>
                <div class="loading-dots">
                    <div class="loading-dot"></div>
                    <div class="loading-dot"></div>
                    <div class="loading-dot"></div>
                </div>
            `;
            generateBtn.disabled = true;
        }
    }

    // Token System Functions
    async function loadTokenBalance() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action: 'get_token_balance' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Check for permanent access first (highest priority)
                if (data.permanent_access && data.permanent_access.active) {
                    // Show crown symbol for permanent access
                    document.getElementById('token-balance').innerHTML = '<i class="fas fa-crown text-emerald-400"></i>';
                    
                    // Show permanent access status
                    showPermanentAccessStatus(data.permanent_access);
                    hideTimedAccessStatus();
                    
                    // Hide payment options and VIP redeem since user has lifetime access
                    hidePaymentOptionsForLifetimeUser();
                } else if (data.timed_access && data.timed_access.active) {
                    // Show infinity symbol for timed access
                    document.getElementById('token-balance').innerHTML = '<i class="fas fa-infinity text-yellow-400"></i>';
                    
                    // Show timed access status
                    showTimedAccessStatus(data.timed_access);
                    hidePermanentAccessStatus();
                } else {
                    // Show regular token count
                    document.getElementById('token-balance').textContent = data.tokens;
                    hideTimedAccessStatus();
                    hidePermanentAccessStatus();
                    
                    // Show payment options since user doesn't have lifetime access
                    showPaymentOptionsForRegularUser();
                }
                
                document.getElementById('free-generates').textContent = data.free_generates_remaining;
                
                // Update countdown visibility based on free generates
                updateCountdownVisibility(data.free_generates_remaining);
            }
        } catch (error) {
            console.error('Error loading token balance:', error);
        }
    }
    
    // Countdown Timer Functions
    function updateCountdownVisibility(freeGeneratesRemaining) {
        const countdownContainer = document.getElementById('countdown-container');
        
        if (freeGeneratesRemaining === 0) {
            countdownContainer.classList.remove('hidden');
            startCountdownTimer();
        } else {
            countdownContainer.classList.add('hidden');
            if (window.countdownInterval) {
                clearInterval(window.countdownInterval);
            }
        }
    }
    
    function startCountdownTimer() {
        function updateTimer() {
            const now = new Date();
            const tomorrow = new Date(now);
            tomorrow.setDate(tomorrow.getDate() + 1);
            tomorrow.setHours(0, 0, 0, 0); // Set to midnight
            
            const timeDiff = tomorrow.getTime() - now.getTime();
            
            if (timeDiff <= 0) {
                // Reset happened, reload token balance
                loadTokenBalance();
                return;
            }
            
            const hours = Math.floor(timeDiff / (1000 * 60 * 60));
            const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);
            
            const timerElement = document.getElementById('countdown-timer');
            if (timerElement) {
                timerElement.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }
        
        // Update immediately
        updateTimer();
        
        // Clear existing interval if any
        if (window.countdownInterval) {
            clearInterval(window.countdownInterval);
        }
        
        // Update every second
        window.countdownInterval = setInterval(updateTimer, 1000);
    }
    
    async function loadWalletBalance() {
        try {
            const response = await fetch('api-wallet.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action: 'get_balance' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('wallet-balance').textContent = '₱' + parseFloat(data.balance).toFixed(2);
                // Also update the timed access modal balance if it exists
                const timedBalance = document.getElementById('wallet-balance-timed');
                if (timedBalance) {
                    timedBalance.textContent = '₱' + parseFloat(data.balance).toFixed(2);
                }
                // Also update the permanent access modal balance if it exists
                const permanentBalance = document.getElementById('wallet-balance-permanent');
                if (permanentBalance) {
                    permanentBalance.textContent = '₱' + parseFloat(data.balance).toFixed(2);
                }
            }
        } catch (error) {
            console.error('Error loading wallet balance:', error);
            document.getElementById('wallet-balance').textContent = '₱0.00';
            const timedBalance = document.getElementById('wallet-balance-timed');
            if (timedBalance) {
                timedBalance.textContent = '₱0.00';
            }
            const permanentBalance = document.getElementById('wallet-balance-permanent');
            if (permanentBalance) {
                permanentBalance.textContent = '₱0.00';
            }
        }
    }
    
    function updateTotalCost() {
        const quantity = parseInt(document.getElementById('token-quantity').value) || 1;
        const costPerToken = 20.00;
        const totalCost = quantity * costPerToken;
        document.getElementById('total-cost').textContent = '₱' + totalCost.toFixed(2);
    }
    
    async function handleTokenPurchase(e) {
        e.preventDefault();
        
        const quantity = parseInt(document.getElementById('token-quantity').value) || 1;
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'Purchasing...';
        
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'buy_tokens',
                    token_count: quantity
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                closeModal('buyTokensModal');
                loadTokenBalance();
                
                // Show success message
                showTemporaryMessage('success', data.message);
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            showTemporaryMessage('error', 'Network error. Please try again.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }
    
    function showTemporaryMessage(type, message) {
        // Remove any existing messages first
        const existingMessages = document.querySelectorAll('.temp-message');
        existingMessages.forEach(msg => msg.remove());
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `temp-message fixed top-4 right-4 z-[9999] transform translate-x-full transition-all duration-500 ease-out`;
        
        const isSuccess = type === 'success';
        
        messageDiv.innerHTML = `
            <div class="flex items-center gap-3 px-4 py-3 rounded-xl shadow-2xl backdrop-blur-lg border max-w-xs ${
                isSuccess 
                    ? 'bg-gradient-to-r from-green-500/90 to-emerald-500/90 border-green-400/30 text-white' 
                    : 'bg-gradient-to-r from-red-500/90 to-pink-500/90 border-red-400/30 text-white'
            }">
                <div class="flex-shrink-0">
                    <i class="fas ${isSuccess ? 'fa-check-circle' : 'fa-exclamation-triangle'} text-lg"></i>
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium truncate">${message}</p>
                </div>
                <button onclick="this.closest('.temp-message').remove()" class="flex-shrink-0 ml-2 hover:bg-white/20 rounded-full p-1 transition-colors">
                    <i class="fas fa-times text-xs"></i>
                </button>
            </div>
        `;
        
        document.body.appendChild(messageDiv);
        
        // Trigger entrance animation
        requestAnimationFrame(() => {
            messageDiv.classList.remove('translate-x-full');
            messageDiv.classList.add('translate-x-0');
        });
        
        // Auto-remove after 4 seconds with exit animation
        setTimeout(() => {
            messageDiv.classList.add('translate-x-full', 'opacity-0');
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.remove();
                }
            }, 500);
        }, 4000);
    }
    
    // Update total cost on page load
    updateTotalCost();
    
    // Timed Access Functions
    let selectedTimedAccess = null;
    let timedAccessInterval = null;
    
    // Make functions globally available to avoid conflicts
    window.selectTimedAccess = function(type, cost) {
        selectedTimedAccess = { type, cost };
        
        // Update radio buttons
        document.getElementById('access-5min').checked = (type === '5min');
        document.getElementById('access-15min').checked = (type === '15min');
        
        // Update selection info
        const info = document.getElementById('selected-access-info');
        const text = document.getElementById('selected-access-text');
        const costElement = document.getElementById('selected-access-cost');
        
        text.textContent = type === '5min' ? '5 Minutes Unlimited' : '15 Minutes Unlimited';
        costElement.textContent = `₱${cost}`;
        costElement.className = `text-lg font-bold ${type === '5min' ? 'text-yellow-400' : 'text-orange-400'}`;
        
        info.classList.remove('hidden');
        
        // Enable purchase button
        document.getElementById('purchase-timed-access-btn').disabled = false;
    };
    
    window.handleTimedAccessPurchase = async function() {
        if (!selectedTimedAccess) {
            showTemporaryMessage('error', 'Please select an access type');
            return;
        }
        
        const purchaseBtn = document.getElementById('purchase-timed-access-btn');
        const originalText = purchaseBtn.textContent;
        
        purchaseBtn.disabled = true;
        purchaseBtn.textContent = 'Processing...';
        
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'buy_timed_access',
                    access_type: selectedTimedAccess.type,
                    cost: selectedTimedAccess.cost
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                closeModal('buyTimedAccessModal');
                loadTokenBalance();
                
                showTemporaryMessage('success', data.message);
                
                // Reset selection
                selectedTimedAccess = null;
                document.getElementById('selected-access-info').classList.add('hidden');
                document.getElementById('purchase-timed-access-btn').disabled = true;
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            showTemporaryMessage('error', 'Network error. Please try again.');
        } finally {
            purchaseBtn.disabled = false;
            purchaseBtn.textContent = originalText;
        }
    };
    
    // Permanent Access Functions
    window.handlePermanentAccessPurchase = async function() {
        const purchaseBtn = document.getElementById('purchase-permanent-access-btn');
        const originalText = purchaseBtn.textContent;
        
        purchaseBtn.disabled = true;
        purchaseBtn.textContent = 'Processing...';
        
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'buy_permanent_access',
                    cost: 299.00
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                closeModal('buyPermanentAccessModal');
                loadTokenBalance();
                
                showTemporaryMessage('success', data.message);
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            showTemporaryMessage('error', 'Network error. Please try again.');
        } finally {
            purchaseBtn.disabled = false;
            purchaseBtn.textContent = originalText;
        }
    };
    
    function showPermanentAccessStatus(permanentAccess) {
        const statusDiv = document.getElementById('permanent-access-status');
        statusDiv.classList.remove('hidden');
    }
    
    function hidePermanentAccessStatus() {
        const statusDiv = document.getElementById('permanent-access-status');
        statusDiv.classList.add('hidden');
    }
    
    function showTimedAccessStatus(timedAccess) {
        const statusDiv = document.getElementById('timed-access-status');
        const countdownElement = document.getElementById('timed-access-countdown');
        
        statusDiv.classList.remove('hidden');
        
        // Start countdown
        startTimedAccessCountdown(timedAccess.end_time);
    }
    
    function hideTimedAccessStatus() {
        const statusDiv = document.getElementById('timed-access-status');
        statusDiv.classList.add('hidden');
        
        if (timedAccessInterval) {
            clearInterval(timedAccessInterval);
            timedAccessInterval = null;
        }
    }
    
    function startTimedAccessCountdown(endTime) {
        if (timedAccessInterval) {
            clearInterval(timedAccessInterval);
        }
        
        function updateTimedCountdown() {
            const now = new Date().getTime();
            const end = new Date(endTime).getTime();
            const timeDiff = end - now;
            
            if (timeDiff <= 0) {
                // Time expired
                hideTimedAccessStatus();
                loadTokenBalance(); // Refresh to show updated status
                showTemporaryMessage('info', 'Unlimited access expired');
                return;
            }
            
            const minutes = Math.floor(timeDiff / (1000 * 60));
            const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);
            
            const countdownElement = document.getElementById('timed-access-countdown');
            if (countdownElement) {
                countdownElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }
        
        // Update immediately
        updateTimedCountdown();
        
        // Update every second
        timedAccessInterval = setInterval(updateTimedCountdown, 1000);
    }
    
    // Function to check if user has premium section access
    window.checkPremiumAccess = async function() {
        try {
            // Check wallet API for paid premium access
            const walletResponse = await fetch('api-wallet.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action: 'check_premium_access' })
            });
            
            const walletData = await walletResponse.json();
            if (walletData.has_access) {
                return true;
            }
            
            // Check token API for VIP code premium access
            const tokenResponse = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action: 'check_vip_premium_access' })
            });
            
            const tokenData = await tokenResponse.json();
            return tokenData.has_access || false;
        } catch (error) {
            console.error('Error checking premium access:', error);
            return false;
        }
    };
    
    // Function to show premium section purchase confirmation
    window.purchasePremiumSection = function() {
        showModal('premiumConfirmModal');
    };
    
    // Function to actually purchase premium section access
    window.confirmPremiumPurchase = async function() {
        // Close confirmation modal first
        closeModal('premiumConfirmModal');
        
        try {
            const price = 49;
            
            // Check wallet balance first
            const balanceResponse = await fetch('api-wallet.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action: 'get_balance' })
            });
            
            const balanceData = await balanceResponse.json();
            
            if (balanceData.success) {
                const balance = parseFloat(balanceData.balance);
                
                if (balance < price) {
                    showTemporaryMessage('error', `Insufficient balance. You need ₱${price} but only have ₱${balance.toFixed(2)}`);
                    return;
                }
                
                // Process the purchase
                const purchaseResponse = await fetch('api-wallet.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ 
                        action: 'deduct_balance', 
                        amount: price,
                        reason: 'Premium Section Access',
                        type: 'premium_access'
                    })
                });
                
                const purchaseData = await purchaseResponse.json();
                
                if (purchaseData.success) {
                    // Show success message
                    showTemporaryMessage('success', 'Premium section unlocked! Enjoy instant access.');
                    
                    // Unlock the section
                    unlockPremiumSection();
                } else {
                    showTemporaryMessage('error', purchaseData.error || 'Purchase failed');
                }
            } else {
                showTemporaryMessage('error', 'Failed to check wallet balance');
            }
        } catch (error) {
            console.error('Error purchasing premium section:', error);
            showTemporaryMessage('error', 'Network error. Please try again.');
        }
    };
    
    // Function to unlock premium section UI
    window.unlockPremiumSection = function() {
        document.getElementById('locked-content').style.display = 'none';
        document.getElementById('unlock-overlay').style.display = 'none';
        document.getElementById('unlocked-content').style.display = 'block';
    };
    
    // Function to open product links (requires premium access)
    window.openProductLink = async function(goodsId, productName) {
        try {
            // Generate and open the gift link
            const baseUrl = "https://app.temu.com/ph-en/kuiper/un1.html?subj=feed-un&_bg_fs=1&_p_mat1_type=3&_p_jump_id=722&_x_vst_scene=adg&goods_id=";
            const giftLink = baseUrl + goodsId;
            
            // Show success message
            showTemporaryMessage('success', `Opening ${productName} gift link...`);
            
            // Open the gift link
            setTimeout(() => {
                window.open(giftLink, '_blank');
            }, 1000);
        } catch (error) {
            console.error('Error opening product link:', error);
            showTemporaryMessage('error', 'Network error. Please try again.');
        }
    };
    
    // Lifetime Access UI Management
    function hidePaymentOptionsForLifetimeUser() {
        // Hide all payment buttons
        const purchaseOptions = document.getElementById('purchase-options');
        const lifetimeNotice = document.getElementById('lifetime-access-notice');
        const vipRedeemSection = document.getElementById('vip-redeem-section');
        
        if (purchaseOptions) {
            purchaseOptions.style.display = 'none';
        }
        
        if (lifetimeNotice) {
            lifetimeNotice.classList.remove('hidden');
        }
        
        // Hide and disable VIP redeem section
        if (vipRedeemSection) {
            vipRedeemSection.style.display = 'none';
        }
    }
    
    function showPaymentOptionsForRegularUser() {
        // Show all payment buttons
        const purchaseOptions = document.getElementById('purchase-options');
        const lifetimeNotice = document.getElementById('lifetime-access-notice');
        const vipRedeemSection = document.getElementById('vip-redeem-section');
        
        if (purchaseOptions) {
            purchaseOptions.style.display = 'block';
        }
        
        if (lifetimeNotice) {
            lifetimeNotice.classList.add('hidden');
        }
        
        // Show VIP redeem section
        if (vipRedeemSection) {
            vipRedeemSection.style.display = 'block';
        }
    }
    
    // VIP Redeem Code Functions
    window.toggleRedeemSection = function() {
        const section = document.getElementById('redeem-section');
        const arrow = document.getElementById('redeem-arrow');
        const isHidden = section.classList.contains('hidden');
        
        if (isHidden) {
            section.classList.remove('hidden');
            arrow.classList.add('rotate-180');
            // Focus on input when opened
            setTimeout(() => {
                document.getElementById('redeem-code-input').focus();
            }, 100);
        } else {
            section.classList.add('hidden');
            arrow.classList.remove('rotate-180');
        }
    };
    
    window.handleRedeemCode = async function(e) {
        e.preventDefault();
        
        const codeInput = document.getElementById('redeem-code-input');
        const redeemBtn = document.getElementById('redeem-btn');
        const code = codeInput.value.trim().toUpperCase();
        
        if (!code) {
            showTemporaryMessage('error', 'Please enter a VIP code');
            codeInput.focus();
            return;
        }
        
        const originalText = redeemBtn.innerHTML;
        redeemBtn.disabled = true;
        redeemBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Redeeming...';
        
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'redeem_vip_code',
                    code: code
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Clear the input
                codeInput.value = '';
                
                // Show success message
                showTemporaryMessage('success', data.message);
                
                // Refresh token balance to show updated status
                loadTokenBalance();
                
                // Collapse the redeem section
                document.getElementById('redeem-section').classList.add('hidden');
                document.getElementById('redeem-arrow').classList.remove('rotate-180');
                
                // Special handling for different reward types
                if (data.reward_type === 'lifetime_access') {
                    setTimeout(() => {
                        showTemporaryMessage('success', '🎉 Welcome to VIP! You now have lifetime unlimited access!');
                    }, 2000);
                } else if (data.reward_type === 'timed_access') {
                    setTimeout(() => {
                        showTemporaryMessage('success', `⏰ ${data.duration} minutes of unlimited access activated!`);
                    }, 2000);
                } else if (data.reward_type === 'premium_section') {
                    // Automatically unlock the premium section
                    unlockPremiumSection();
                    setTimeout(() => {
                        showTemporaryMessage('success', '🎁 Ready-to-Use Products section unlocked!');
                    }, 2000);
                }
            } else {
                showTemporaryMessage('error', data.error || 'Invalid or expired VIP code');
                codeInput.focus();
                codeInput.select();
            }
        } catch (error) {
            console.error('Redeem code error:', error);
            showTemporaryMessage('error', 'Network error. Please try again.');
        } finally {
            redeemBtn.disabled = false;
            redeemBtn.innerHTML = originalText;
        }
    };
    
    // Check premium access on page load
    document.addEventListener('DOMContentLoaded', async function() {
        const hasAccess = await checkPremiumAccess();
        if (hasAccess) {
            unlockPremiumSection();
        }
    });
    
    // Chat System Functions
    let chatMode = 'chat';
    let chatInterval = null;
    let onlineUsersInterval = null;
    let typingInterval = null;
    let lastMessageId = 0;
    let isChatOpen = false;
    let typingTimer = null;
    let isTyping = false;
    let messagesSent = 0;
    let reactionEmojis = {
        'like': '👍',
        'love': '❤️', 
        'laugh': '😂',
        'wow': '😮',
        'sad': '😢',
        'angry': '😠'
    };
    
    // Sound effects
    const notificationSound = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmEaCSGP3PPCciIGKojH9dqZSwoTZLPm76NPEw5OqMfmu3ElaRpHqODitmdcHw==');
    notificationSound.volume = 0.3;
    
    function initChatSystem() {
        loadChatMessages();
        loadTransferLimit();
        loadOnlineUsers();
        
        // Auto-refresh chat every 3 seconds when open
        chatInterval = setInterval(() => {
            if (isChatOpen) {
                loadNewMessages();
                loadTypingUsers();
            }
        }, 3000);
        
        // Update online users every 10 seconds
        onlineUsersInterval = setInterval(() => {
            if (isChatOpen) {
                loadOnlineUsers();
                updateOnlineStatus();
            }
        }, 10000);
        
        // Set up input event handlers
        const chatInput = document.getElementById('chat-input');
        
        // Enter key to send message
        chatInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendMessage();
            }
        });
        
        // Typing indicators
        chatInput.addEventListener('input', function() {
            if (!isTyping) {
                setTypingStatus(true);
                isTyping = true;
            }
            
            clearTimeout(typingTimer);
            typingTimer = setTimeout(() => {
                setTypingStatus(false);
                isTyping = false;
            }, 2000);
        });
        
        // Close emoji picker when clicking outside
        document.addEventListener('click', function(e) {
            const emojiPicker = document.getElementById('emoji-picker');
            const emojiBtn = document.querySelector('.emoji-toggle-btn');
            const emojiOptionBtn = document.querySelector('.chat-option-btn[onclick="toggleEmojiPicker()"]');
            
            if (!emojiPicker.contains(e.target) && e.target !== emojiBtn && e.target !== emojiOptionBtn) {
                emojiPicker.classList.remove('show');
            }
        });
    }
    
    function toggleChat() {
        const modal = document.getElementById('full-chat-modal');
        const isShowing = modal.classList.contains('show');
        
        if (isShowing) {
            modal.classList.remove('show');
            document.body.style.overflow = 'auto';
            isChatOpen = false;
        } else {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
            isChatOpen = true;
            loadChatMessages();
            // Focus on input when opened
            setTimeout(() => {
                document.getElementById('chat-input').focus();
            }, 300);
        }
    }
    
    function setChatMode(mode) {
        chatMode = mode;
        
        // Update button states
        document.querySelectorAll('.chat-option-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        if (mode === 'chat') {
            document.querySelector('.chat-option-btn[onclick="setChatMode(\'chat\')"]').classList.add('active');
            document.getElementById('token-transfer-controls').classList.remove('show');
            document.getElementById('chat-input').placeholder = 'Type a message...';
        } else if (mode === 'transfer') {
            document.querySelector('.chat-option-btn[onclick="setChatMode(\'transfer\')"]').classList.add('active');
            document.getElementById('token-transfer-controls').classList.add('show');
            document.getElementById('chat-input').placeholder = 'Optional message with transfer...';
            loadTransferLimit();
        }
    }
    
    async function sendMessage() {
        const input = document.getElementById('chat-input');
        const message = input.value.trim();
        
        if (chatMode === 'chat') {
            if (!message) {
                showTemporaryMessage('error', 'Please enter a message');
                return;
            }
            
            await sendChatMessage(message, 'chat');
        } else if (chatMode === 'transfer') {
            const targetUsername = document.getElementById('target-username').value.trim();
            const tokenAmount = parseInt(document.getElementById('token-amount').value);
            
            if (!targetUsername || !tokenAmount) {
                showTemporaryMessage('error', 'Please enter username and token amount');
                return;
            }
            
            if (tokenAmount < 1 || tokenAmount > 10) {
                showTemporaryMessage('error', 'Token amount must be between 1 and 10');
                return;
            }
            
            await sendTokenTransfer(targetUsername, tokenAmount, message);
        }
        
        // Clear inputs
        input.value = '';
        if (chatMode === 'transfer') {
            document.getElementById('target-username').value = '';
            document.getElementById('token-amount').value = '';
        }
    }
    
    async function sendChatMessage(message, messageType) {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'send_chat_message',
                    message: message,
                    message_type: messageType
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                loadNewMessages();
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            console.error('Chat error:', error);
            showTemporaryMessage('error', 'Failed to send message');
        }
    }
    
    async function sendTokenTransfer(targetUsername, tokenAmount, message) {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'send_chat_message',
                    message: message || `Sending ${tokenAmount} tokens`,
                    message_type: 'token_transfer',
                    token_amount: tokenAmount,
                    target_username: targetUsername
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showTemporaryMessage('success', `Sent ${tokenAmount} tokens to @${targetUsername}`);
                loadNewMessages();
                loadTokenBalance();
                loadTransferLimit();
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            console.error('Transfer error:', error);
            showTemporaryMessage('error', 'Failed to send tokens');
        }
    }
    
    async function loadChatMessages() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'get_chat_messages',
                    limit: 50
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                displayChatMessages(data.messages, true); // true = full reload
                if (data.messages.length > 0) {
                    lastMessageId = Math.max(...data.messages.map(m => m.id));
                }
            }
        } catch (error) {
            console.error('Load messages error:', error);
        }
    }
    
    async function loadNewMessages() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'get_chat_messages',
                    limit: 10,
                    after_id: lastMessageId
                })
            });
            
            const data = await response.json();
            
            if (data.success && data.messages.length > 0) {
                displayChatMessages(data.messages, false); // false = append only
                lastMessageId = Math.max(...data.messages.map(m => m.id));
            }
        } catch (error) {
            console.error('Load new messages error:', error);
        }
    }
    
    function displayChatMessages(messages, fullReload = true) {
        const container = document.getElementById('chat-messages');
        const shouldScrollToBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 50;
        
        if (fullReload) {
            container.innerHTML = '';
        }
        
        messages.forEach(msg => {
            // Check if message already exists (prevent duplicates)
            if (!fullReload && document.querySelector(`[data-message-id="${msg.id}"]`)) {
                return;
            }
            
            const messageDiv = document.createElement('div');
            messageDiv.setAttribute('data-message-id', msg.id);
            
            if (msg.message_type === 'token_transfer') {
                messageDiv.className = 'chat-message token-transfer';
                messageDiv.innerHTML = `
                    <div class="message-text">${escapeHtml(msg.message)}</div>
                    <div class="message-time">${formatTime(msg.created_at)}</div>
                `;
            } else {
                messageDiv.className = `chat-message ${msg.is_own_message ? 'own' : 'other'}`;
                
                let messageContent = `
                    ${msg.reply_to_message_id ? `<div class="reply-to">
                        <div class="reply-username">@${escapeHtml(msg.sender_username)}</div>
                        <div>Replying to message</div>
                    </div>` : ''}
                    <div class="message-username">@${escapeHtml(msg.sender_username)}</div>
                    <div class="message-text">${escapeHtml(msg.message)}</div>
                    <div class="message-time">
                        ${formatTime(msg.created_at)}
                        ${msg.is_edited ? '<span class="message-edited">(edited)</span>' : ''}
                    </div>
                `;
                
                // Add reactions
                if (msg.reactions && msg.reactions.length > 0) {
                    const reactionsHtml = msg.reactions.map(reaction => 
                        `<button class="reaction-btn ${reaction.user_reacted ? 'user-reacted' : ''}" onclick="toggleReaction(${msg.id}, '${reaction.type}')">
                            <span class="reaction-emoji">${reactionEmojis[reaction.type] || reaction.type}</span>
                            <span class="reaction-count">${reaction.count}</span>
                        </button>`
                    ).join('');
                    messageContent += `<div class="message-reactions">${reactionsHtml}</div>`;
                }
                
                // Add message actions for own messages
                if (msg.is_own_message) {
                    messageContent += `
                        <div class="message-actions">
                            <button class="message-action-btn" onclick="editMessage(${msg.id})" title="Edit">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="message-action-btn" onclick="deleteMessage(${msg.id})" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    `;
                } else {
                    // Add reaction button for other's messages
                    messageContent += `
                        <div class="message-actions">
                            <button class="message-action-btn" onclick="showReactionPicker(${msg.id})" title="React">
                                <i class="fas fa-smile"></i>
                            </button>
                            <button class="message-action-btn" onclick="blockUser('${msg.sender_username}')" title="Block User">
                                <i class="fas fa-ban"></i>
                            </button>
                        </div>
                    `;
                }
                
                messageDiv.innerHTML = messageContent;
            }
            
            container.appendChild(messageDiv);
            
            // Play notification sound for new messages from others
            if (!fullReload && !msg.is_own_message) {
                playNotificationSound();
            }
        });
        
        // Auto-scroll to bottom if user was already at bottom or for new messages
        if (shouldScrollToBottom || !fullReload) {
            setTimeout(() => {
                container.scrollTop = container.scrollHeight;
            }, 100);
        }
        
        // Update message count
        if (!fullReload) {
            messagesSent += messages.filter(msg => msg.is_own_message).length;
            updateMessageCount();
        }
    }
    
    async function loadTransferLimit() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'get_transfer_limit'
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                const transferInfo = document.getElementById('transfer-info');
                transferInfo.textContent = `Daily limit: ${data.remaining}/${data.daily_limit} tokens remaining`;
            }
        } catch (error) {
            console.error('Load transfer limit error:', error);
        }
    }
    
    function formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) { // Less than 1 minute
            return 'Just now';
        } else if (diff < 3600000) { // Less than 1 hour
            return Math.floor(diff / 60000) + 'm ago';
        } else if (diff < 86400000) { // Less than 24 hours
            return Math.floor(diff / 3600000) + 'h ago';
        } else {
            return date.toLocaleDateString();
        }
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Advanced Chat Functions
    
    async function loadOnlineUsers() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_online_users' })
            });
            
            const data = await response.json();
            if (data.success) {
                displayOnlineUsers(data.users);
            }
        } catch (error) {
            console.error('Load online users error:', error);
        }
    }
    
    function displayOnlineUsers(users) {
        const container = document.getElementById('online-users');
        const countElement = document.getElementById('online-count');
        
        container.innerHTML = '';
        countElement.textContent = users.length;
        
        users.forEach(user => {
            const userDiv = document.createElement('div');
            userDiv.className = 'online-user';
            userDiv.innerHTML = `
                <div class="user-status-dot"></div>
                <div class="user-name">${escapeHtml(user.username)}</div>
            `;
            userDiv.title = user.status_message || 'Online';
            container.appendChild(userDiv);
        });
    }
    
    async function updateOnlineStatus() {
        try {
            await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'update_online_status' })
            });
        } catch (error) {
            console.error('Update online status error:', error);
        }
    }
    
    async function setTypingStatus(typing) {
        try {
            await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'set_typing', typing: typing })
            });
        } catch (error) {
            console.error('Set typing status error:', error);
        }
    }
    
    async function loadTypingUsers() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_typing_users' })
            });
            
            const data = await response.json();
            if (data.success) {
                displayTypingIndicators(data.typing_users);
            }
        } catch (error) {
            console.error('Load typing users error:', error);
        }
    }
    
    function displayTypingIndicators(typingUsers) {
        const container = document.getElementById('typing-indicators');
        
        if (typingUsers.length === 0) {
            container.innerHTML = '';
            return;
        }
        
        let text = '';
        if (typingUsers.length === 1) {
            text = `${typingUsers[0]} is typing...`;
        } else if (typingUsers.length === 2) {
            text = `${typingUsers[0]} and ${typingUsers[1]} are typing...`;
        } else {
            text = `${typingUsers.length} people are typing...`;
        }
        
        container.innerHTML = `<div class="typing-indicator">${text}</div>`;
    }
    
    async function toggleReaction(messageId, reactionType) {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    action: 'react_to_message', 
                    message_id: messageId, 
                    reaction: reactionType 
                })
            });
            
            const data = await response.json();
            if (data.success) {
                loadNewMessages(); // Reload to show updated reactions
            } else {
                showTemporaryMessage('error', data.error);
            }
        } catch (error) {
            console.error('Toggle reaction error:', error);
        }
    }
    
    function showReactionPicker(messageId) {
        const reactions = ['like', 'love', 'laugh', 'wow', 'sad', 'angry'];
        const picker = document.createElement('div');
        picker.className = 'emoji-picker show';
        picker.style.position = 'absolute';
        picker.style.zIndex = '1000';
        
        const grid = document.createElement('div');
        grid.className = 'emoji-grid';
        
        reactions.forEach(reaction => {
            const btn = document.createElement('button');
            btn.className = 'emoji-btn';
            btn.innerHTML = reactionEmojis[reaction];
            btn.onclick = () => {
                toggleReaction(messageId, reaction);
                picker.remove();
            };
            grid.appendChild(btn);
        });
        
        picker.appendChild(grid);
        
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        messageElement.style.position = 'relative';
        messageElement.appendChild(picker);
        
        setTimeout(() => picker.remove(), 5000);
    }
    
    async function editMessage(messageId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"] .message-text`);
        const currentText = messageElement.textContent;
        
        const newText = prompt('Edit message:', currentText);
        if (newText && newText !== currentText) {
            try {
                const response = await fetch('api/token_actions.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        action: 'edit_message', 
                        message_id: messageId, 
                        new_message: newText 
                    })
                });
                
                const data = await response.json();
                if (data.success) {
                    loadNewMessages();
                    showTemporaryMessage('success', 'Message updated');
                } else {
                    showTemporaryMessage('error', data.error);
                }
            } catch (error) {
                console.error('Edit message error:', error);
            }
        }
    }
    
    async function deleteMessage(messageId) {
        if (confirm('Delete this message?')) {
            try {
                const response = await fetch('api/token_actions.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        action: 'delete_message', 
                        message_id: messageId 
                    })
                });
                
                const data = await response.json();
                if (data.success) {
                    loadNewMessages();
                    showTemporaryMessage('success', 'Message deleted');
                } else {
                    showTemporaryMessage('error', data.error);
                }
            } catch (error) {
                console.error('Delete message error:', error);
            }
        }
    }
    
    async function blockUser(username) {
        if (confirm(`Block user @${username}? You won't see their messages anymore.`)) {
            try {
                const response = await fetch('api/token_actions.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        action: 'block_user', 
                        username: username 
                    })
                });
                
                const data = await response.json();
                if (data.success) {
                    loadChatMessages(); // Reload to hide blocked user's messages
                    showTemporaryMessage('success', data.message);
                } else {
                    showTemporaryMessage('error', data.error);
                }
            } catch (error) {
                console.error('Block user error:', error);
            }
        }
    }
    
    function toggleEmojiPicker() {
        const picker = document.getElementById('emoji-picker');
        picker.classList.toggle('show');
    }
    
    function insertEmoji(emoji) {
        const input = document.getElementById('chat-input');
        const cursorPos = input.selectionStart;
        const text = input.value;
        const newText = text.slice(0, cursorPos) + emoji + text.slice(cursorPos);
        input.value = newText;
        input.focus();
        input.setSelectionRange(cursorPos + emoji.length, cursorPos + emoji.length);
        
        document.getElementById('emoji-picker').classList.remove('show');
    }
    
    function playNotificationSound() {
        if (notificationSound && hasUserInteracted) {
            notificationSound.currentTime = 0;
            notificationSound.play().catch(() => {});
        }
    }
    
    function updateMessageCount() {
        const element = document.getElementById('messages-sent');
        if (element) {
            element.textContent = messagesSent;
        }
    }
    
    async function updateTransferStats() {
        try {
            const response = await fetch('api/token_actions.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_transfer_limit' })
            });
            
            const data = await response.json();
            if (data.success) {
                const element = document.getElementById('tokens-sent-today');
                if (element) {
                    element.textContent = data.tokens_sent_today;
                }
            }
        } catch (error) {
            console.error('Update transfer stats error:', error);
        }
    }
    
    // Enhanced mobile responsiveness
    function adjustChatForMobile() {
        if (window.innerWidth <= 768) {
            const container = document.querySelector('.chat-container');
            container.style.gridTemplateColumns = '1fr';
            
            const sidebar = document.querySelector('.chat-sidebar');
            sidebar.style.display = 'none';
        }
    }
    
    window.addEventListener('resize', adjustChatForMobile);
    
    // Generator Selection Functions
    window.selectGenerator = function(type) {
        const modal = document.getElementById('generatorModal');
        const icon = document.getElementById('selected-generator-icon');
        const title = document.getElementById('selected-generator-title');
        const description = document.getElementById('selected-generator-description');
        const form = document.getElementById('selected-generator-form');
        const typeInput = document.getElementById('selected-generator-type');
        const button = document.getElementById('selected-generate-btn');
        const shareInput = document.getElementById('selected-share-link');
        
        if (type === 'standard') {
            icon.className = 'w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-4';
            icon.innerHTML = '<i class="fas fa-gift text-white text-xl"></i>';
            title.textContent = 'Standard Gift Generator';
            description.textContent = 'Creates standard TEMU gift links with optimized parameters for maximum compatibility.';
            typeInput.value = 'standard';
            button.textContent = 'GENERATE STANDARD LINK';
            button.className = 'w-full px-6 py-3 text-sm font-bold text-gray-900 bg-cyan-400 rounded-md hover:bg-white hover:text-black focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-white transition-all duration-200';
            shareInput.className = 'w-full px-4 py-3 text-sm text-gray-200 bg-gray-900/80 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all duration-200 placeholder:text-gray-600';
        } else if (type === 'full_return') {
            icon.className = 'w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center mx-auto mb-4';
            icon.innerHTML = '<i class="fas fa-sync-alt text-white text-xl"></i>';
            title.textContent = 'Full Return Generator';
            description.textContent = 'Creates advanced TEMU links with full return activity parameters for enhanced features and tracking.';
            typeInput.value = 'full_return';
            button.textContent = 'GENERATE RETURN LINK';
            button.className = 'w-full px-6 py-3 text-sm font-bold text-white bg-gradient-to-r from-purple-600 to-pink-600 rounded-md hover:from-purple-700 hover:to-pink-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-purple-600 transition-all duration-200 shadow-lg hover:shadow-xl';
            shareInput.className = 'w-full px-4 py-3 text-sm text-gray-200 bg-gray-900/80 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent transition-all duration-200 placeholder:text-gray-600';
        }
        
        // Clear any previous input
        shareInput.value = '';
        
        // Auto-fill from clipboard if available
        checkModalClipboard(shareInput, type);
        
        // Show the modal
        showModal('generatorModal');
        
        // Focus on the input after modal opens
        setTimeout(() => {
            shareInput.focus();
        }, 300);
    };
    
    // Check clipboard for modal generators
    async function checkModalClipboard(inputElement, generatorType) {
        if (!navigator.clipboard) {
            return;
        }
        
        try {
            const text = await navigator.clipboard.readText();
            if (text && text.length > 10 && text.includes('temu.com')) {
                // Fill the input field
                inputElement.value = text.trim();
                inputElement.style.borderColor = '#10b981';
                inputElement.style.boxShadow = '0 0 0 2px rgba(16, 185, 129, 0.3)';
                
                // Show a subtle indication
                setTimeout(() => {
                    inputElement.style.borderColor = generatorType === 'full_return' ? '#a855f7' : '#06b6d4';
                    inputElement.style.boxShadow = generatorType === 'full_return' ? '0 0 0 2px rgba(168, 85, 247, 0.3)' : '0 0 0 2px rgba(6, 182, 212, 0.3)';
                }, 1500);
            }
        } catch (err) {
            // Silently fail if clipboard access denied
        }
    }
    
    // Make functions globally available
    window.toggleChat = toggleChat;
    window.setChatMode = setChatMode;
    window.sendMessage = sendMessage;
    window.toggleEmojiPicker = toggleEmojiPicker;
    window.insertEmoji = insertEmoji;
    window.toggleReaction = toggleReaction;
    window.showReactionPicker = showReactionPicker;
    window.editMessage = editMessage;
    window.deleteMessage = deleteMessage;
    window.blockUser = blockUser;
    
    // Show appropriate result based on PHP results
    <?php if ($success && $show_result): ?>
        document.addEventListener('DOMContentLoaded', function() {
            // Prevent multiple executions
            if (window.temuRedirectExecuted) {
                return;
            }
            window.temuRedirectExecuted = true;
            
            // Refresh token balance after successful generation
            loadTokenBalance();
            
            // Add a small delay before redirect to ensure everything is loaded
            setTimeout(() => {
                redirectToGift();
            }, 500);
        });
    <?php elseif ($error): ?>
        document.addEventListener('DOMContentLoaded', function() {
            showModal('errorModal');
        });
    <?php endif; ?>

</script>


</body>
</html>
