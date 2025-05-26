def get_device_info(request):
    """
    Extract device information from the request headers
    """
    user_agent = request.headers.get('User-Agent', '')
    
    # Determine browser
    browser = "Unknown"
    if "Firefox" in user_agent:
        browser = "Firefox"
    elif "Chrome" in user_agent and "Edg" not in user_agent:
        browser = "Chrome"
    elif "Edg" in user_agent:
        browser = "Edge"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser = "Safari"
    elif "Opera" in user_agent or "OPR" in user_agent:
        browser = "Opera"
    
    # Determine OS
    os = "Unknown"
    if "Windows" in user_agent:
        os = "Windows"
    elif "Mac OS" in user_agent:
        os = "macOS"
    elif "iPhone" in user_agent:
        os = "iOS"
    elif "Android" in user_agent:
        os = "Android"
    elif "Linux" in user_agent:
        os = "Linux"
    
    # Determine device type
    device = "Unknown"
    if "Mobile" in user_agent or "iPhone" in user_agent:
        device = "Mobile"
    elif "Tablet" in user_agent or "iPad" in user_agent:
        device = "Tablet"
    else:
        device = "Desktop"
    
    return {
        "browser": browser,
        "os": os,
        "device": device,
        "user_agent": user_agent
    }