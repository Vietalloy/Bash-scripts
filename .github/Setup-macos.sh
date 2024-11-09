#!/bin/sh
clear

## Declare global variables, don't modify if you don't know what it is
##pkg_path="/tmp"
pkg_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ad_group="USER\Domain Admins,USER\IT_HotroMacOS,USER\IT_HotroPC"


fancy_echo() {
    local fmt="$1"; shift
    printf "\n$fmt\n" "$@"
}

fancy_echo "[INFO] ----------------------------- [ BOOTSTRAPING ] -----------------------------"
trap 'ret=$?; test $ret -ne 0 && printf "failed\n\n" >&2; exit $ret' EXIT
set -e

# Here we go.. ask for user input ComputerName and AD admin's account to join domain
# Make sure timezone is correct
# Make sure this macbook won't sleep during task run due to network drop

CURRENTNAME=$(hostname)
echo "1. The current ComputerName is" $CURRENTNAME
read -p "Enter the computer name to setup: " computername
echo "2. Enter the AD admin's account which have permission to join domain:"
read -p "AD admin's user: " ad_username
echo ""
read -s -p "AD admin's password: " ad_password
echo ""

 

## -----------------------------------------------------------------------------------------##


## download package to $pkg_path and /dev/null output
function get_pkg {
##    usr="$(echo -n 'ZHNvLXJv' | base64 -d)"
##    passwd="$(echo -n 'UGFzc3cwcmQxMg==' | base64 -d)"
##    nexusPath="https://nexus-dso.techcombank.com.vn/repository/it-devsecops/tools/thirdparty/mac-apps"
##    curl -u $usr:$passwd /$1 -o $pkg_path $nexusPath/$1 > /dev/null 2>&1
	  
    cp "$pkg_path/$1" "$pkg_path/$1"
}

function install_cmd {
    installer -pkg $pkg_path/$1 -target / > /dev/null 2>&1
}

function install_cmd_dmg {
    hdiutil attach $pkg_path/$1 > /dev/null 2>&1
    pushd /Volumes/$2
    cp -R $2.app /Applications/$2.app
    popd
    hdiutil detach /Volumes/$2 > /dev/null 2>&1
}

function install_rosetta2() {
    echo "[INFO] Installing Rosetta2"
    rosetta2_pkg="RosettaUpdateAuto.pkg"
    ## Install Rosetta2, this always run if the device is Macbook M1 (arm64)
    if [[ $(uname -m) == 'arm64' ]]; then
        get_pkg $rosetta2_pkg
        install_cmd $rosetta2_pkg
        /usr/sbin/softwareupdate -install-rosetta -agree-to-license
        echo "[INFO] Rosetta2 Installed"
    else
        echo "This Macbook info is $(uname -m) so do not need to install Rosetta2"
    fi
}

# ## Install xcode commandline tool
#     # xcode-select --install
# if [[ $(xcode-select -p) == "/Library/Developer/CommandLineTools" ]] || [[ $(xcode-select -p) == "/Applications/Xcode.app/Contents/Developer" ]]; then
#     fancy_echo "[INFO] --------------------- Xcode Commandline Tool Installed ---------------------"
# else
#     if [[ $(/usr/bin/sw_vers -productVersion | awk -F. '{ print $1 }') < 12 ]]; then
#         osVersion="bigsur"
#     else
#         osVersion="monterey"
#     fi

#     if [[ $osVersion == "bigsur" ]]; then
#         fancy_echo "[INFO] -------------------- Installing Xcode Commandline Tool ---------------------"
#         get_pkg "CommandLineTools-12.3.pkg"
#         install_cmd "CommandLineTools-12.3.pkg"

#     elif [[ $osVersion == "monterey" ]]; then
#         fancy_echo "[INFO] -------------------- Installing Xcode Commandline Tool ---------------------"
#         get_pkg "CommandLineTools-13.3.pkg"
#         install_cmd "CommandLineTools-13.3.pkg"
#     fi
# fi



function join_domain() {
    ## Set Computer Name then join domain, this stage can be error if domain admin account incorrect or not have permission to join domain
    echo "[INFO] Doing join domain"
    if [[ $(dsconfigad -show | awk '{print$5}'| grep user.techcombank.com.vn) == "" ]]; then
        scutil --set HostName $computername
        scutil --set LocalHostName $computername
        scutil --set ComputerName $computername
        dsconfigad -force -add user.techcombank.com.vn -username $ad_username -password $ad_password \
            -mobile enable -mobileconfirm disable -localhome enable -useuncpath enable \
            groups $ad_group
    else
        echo "[INFO] This Computer has been joined to TCB domain"
    fi

    dsconfigad -groups $ad_group ##Leave it here to ensure command always run, just for sure if above command not correctly configure

    ## Import Internet Certificate
    ## Doesn't find out solution to check condition if the Certificates installed or not -> so this stage always run
    get_pkg "apt2016.crt"
    security authorizationdb write com.apple.trust-settings.admin allow > /dev/null 2>&1
    security add-trusted-cert -r trustRoot -d -k /Library/Keychains/System.keychain $pkg_path/apt2016.crt > /dev/null 2>&1
    rm -rf $pkg_path/apt2016.crt
}

function install_cisco() {
    echo "[INFO] Installing Cisco Anyconnect"
    ## Install Cisco AnyConnect
    if [[ ! -f /opt/cisco/anyconnect/bin/vpn ]]; then
        get_pkg "AnyConnect.pkg"
        get_pkg "ISEPostureCFG.xml"
        get_pkg "acvpn.xml"
        get_pkg "vpn_install_choices.xml"
        get_pkg "TCB-VPN-MacOS.pfx"
        installer -pkg $pkg_path/AnyConnect.pkg -applyChoiceChangesXML $pkg_path/vpn_install_choices.xml -target / > /dev/null 2>&1
        cp $pkg_path/ISEPostureCFG.xml /opt/cisco/anyconnect/iseposture/ISEPostureCFG.xml > /dev/null 2>&1
        cp $pkg_path/acvpn.xml /opt/cisco/anyconnect/profile/acvpn.xml > /dev/null 2>&1
        chmod 755 /opt/cisco/anyconnect/profile/acvpn.xml
        security import $pkg_path/TCB-VPN-MacOS.pfx -k /Library/Keychains/System.keychain \
        -P \Tcb@1234567890 -T "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app" > /dev/null 2>&1

        rm -rf $pkg_path/AnyConnect.pkg
        rm -rf $pkg_path/ISEPostureCFG.xml
        rm -rf $pkg_path/acvpn.xml
        rm -rf $pkg_path/vpn_install_choices.xml
        rm -rf $pkg_path/TCB-VPN-MacOS.pfx
        echo "Cisco AnyConnect Installed"
    else
        echo "Cisco AnyConnect Already Installed"
    fi
}

function install_vnc() {
    ## Install VNC Server then add VNC License
    echo "[INFO] Installing VNC Server"
    vnc_license="88XAF-Z4AE2-2TJLU-XVFSU-6AMLA"
    vnc_pkg=VNC-Server-6.11.0-MacOSX-x86_64.pkg
    if [[ ! -d "/Applications/RealVNC/VNC Server.app" ]]; then
        fancy_echo "[INFO] -------------------------- Installing VNC Server ---------------------------"
        get_pkg $vnc_pkg
        install_cmd $vnc_pkg
        /Library/vnc/vnclicense -add $vnc_license || true > /dev/null 2>&1
        
        ## Enable VNC password 
        config_file="/var/root/.vnc/config.d/vncserver"
        # Update values in the config file
        if [[ -f "$config_file" ]]; then
            sed -i.backup 's~Authentication=.*~Authentication=VncAuth~' "$config_file"
            sed -i.backup 's~Password=.*~Password=8250f17dbea9dfa6~' "$config_file"
            sed -i.backup 's~QueryConnect=.*~QueryConnect=1~' "$config_file"
        else
        cat > "$config_file" << EOF
Authentication=VncAuth
EnableAnalytics=1
EnableAutoUpdateChecks=1
Password=8250f17dbea9dfa6
QueryConnect=1
EOF
        fi

        ## Cleanup
        rm -rf $pkg_path/$vnc_pkg
        echo "[INFO] VNC Server Installed"
    else
        echo "[INFO] VNC Server Already Installed"
    fi
}

# ## Install FireFox
# if [[ ! -d "/Applications/Firefox.app" ]]; then
#     fancy_echo "[INFO] ---------------------------- Installing FireFox ----------------------------"
#     get_pkg "Firefox-113.0.1.dmg"
#     install_cmd_dmg "Firefox-113.0.1.dmg" "Firefox"

#     rm -rf $pkg_path/Firefox-113.0.1.dmg
# else
#     fancy_echo "[INFO] ---------------------------- Firefox Installed -----------------------------"
# fi

function install_intune() {
    echo "[INFO] Installing Company Portal"
    ## Install Intune
    company_portal_pkg="CompanyPortal-Installer.pkg"
    if [[ ! -d "/Applications/Company Portal.app" ]]; then
        fancy_echo "[INFO] -------- Installing Intune --------"
        get_pkg $company_portal_pkg
        install_cmd $company_portal_pkg

        rm -rf $pkg_path/$company_portal_pkg
        echo "Company Portal Installed"
    else
        echo "Company Portal Already Installed"
    fi
}

function install_printer() {
    echo "[INFO] Installing Printer"
    ## Install Printer Server at TDH
    if [[ ! -f /Library/Printers/PPDs/Contents/Resources/CNPZUIRA4551ZU.ppd.gz ]]; then
        fancy_echo "[INFO] ---------------------------- Installing printer at TDH ---------------------"
        get_pkg "shared-printer-driver.pkg"
        get_pkg "CNPZUIRA4545ZU.ppd"
        installer -pkg $pkg_path/shared-printer-driver.pkg -target /
        lpadmin -p TCB_119THD_Print_UD -E -v smb://10.98.8.28/TCB_119THD_Print_UD -P $pkg_path/CNPZUIRA4545ZU.ppd -o printer-is-shared=false -u allow:all

        rm -rf $pkg_path/shared-printer-driver.pkg
        echo "[INFO] Printer Installed"
    else
        echo "[INFO] Printer Already Installed"
    fi
}

function install_webex() {
    ## Install Webex
    echo "[INFO] Installing Webex"
    webex_pkg="Cisco_Webex_Meetings.pkg"
    if [[ ! -f "/Applications/Webex.app/Contents/MacOS/Webex Teams" && ! -d "/Applications/Cisco\ Webex\ Meetings.app" ]]; then
        fancy_echo "[INFO] ---------------------------- Installing Webex ------------------------------"
        get_pkg $webex_pkg
        install_cmd $webex_pkg

        rm -rf $pkg_path/$webex_pkg
        echo "[INFO] Webex installed"
    else
        echo "[INFO] Webex Already installed"
    fi
}

function install_tdoc() {
    ## Install Tdoc
    echo "[INFO] Installing Tdoc"
    tdoc_pkg="TdocPlugins-1.3.pkg"
    if [[ ! -d "/Applications/TdocPlugins.app" ]]; then
        get_pkg $tdoc_pkg
        install_cmd $tdoc_pkg

        rm -rf $pkg_path/$tdoc_pkg
        echo "[INFO] Tdoc Installed"
    else
        echo "[INFO] Tdoc Already Installed"
    fi
}

function install_office365() {
    ## Install Office 365
    echo "[INFO] Installing Office 365"
    office_365_pkg="office365.pkg"
    if [[ ! -d "/Applications/Microsoft Outlook.app" ]]; then
        get_pkg $office_365_pkg
        install_cmd $office_365_pkg

        rm -rf $pkg_path/$office_365_pkg
        echo "[INFO] Office 365 Installed"
    else
        echo "[INFO] Office 365 Already Installed"
    fi
}

function configure_dns() {
    ## Configure DNS
    echo "[INFO] Configure DNS to be able to access network drive"
    dns_list="techcombank.com.vn user.techcombank.com.vn headquarter.techcombank.com.vn"
    if [[ $(networksetup -listallnetworkservices | grep Wi-Fi) == "Wi-Fi" ]]; then
        networksetup -setsearchdomains Wi-Fi \
        $dns_list > /dev/null 2>&1
    fi

    if [[ $(networksetup -listallnetworkservices | grep "USB 10/100/1000 LAN") == "USB 10/100/1000 LAN" ]]; then
        networksetup -setsearchdomains "USB 10/100/1000 LAN" \
        $dns_list > /dev/null 2>&1
    fi
    networksetup -setv6off Wi-Fi > /dev/null 2>&1
    echo "[INFO] Configure DNS Completed"
}

function install_mcafee() {
    install_mcafee_agent
    install_mcafee_ens
    install_mcafee_dlp
}

function install_mcafee_agent() {
    ## Install McAfee
    echo "[INFO] Installing McAfee Agent"
    mc_agent_pkg="install.sh"
    if [[ ! -f "/Library/McAfee/cma/scripts/uninstall.sh" ]]; then
        get_pkg $mc_agent_pkg
        chmod 755 $pkg_path/$mc_agent_pkg
        $pkg_path/$mc_agent_pkg -i > /dev/null 2>&1

        rm -rf $pkg_path/$mc_agent_pkg
        echo "[INFO] McAfee Agent Installed"
    else
        echo "[INFO] McAfee Agent Already Installed"
    fi
}

function install_mcafee_ens() {
    ## Install McAfee ENS
    echo "[INFO] Installing McAfee ENS"
    mc_ens_pkg="McAfee-Endpoint-Security-for-Mac-10.7.8-RTW-standalone-186.pkg"

    if [[ ! -d "/usr/local/McAfee/AntiMalware/VShieldScanManager.app" ]]; then
        get_pkg $mc_ens_pkg
       install_cmd $mc_ens_pkg

        rm -rf $pkg_path/$mc_ens_pkg
        echo "[INFO] McAfee ENS Installed"
    else
        echo "[INFO] McAfee ENS Already Installed"
    fi
}

function install_mcafee_dlp() {
    ## Install McAfee DLP
    echo "[INFO] Installing McAfee DLP"
    mc_dlp_pkg="DlpAgentInstaller.pkg"
    if [[ ! -d "/usr/local/McAfee/DlpAgent" ]]; then
        get_pkg $mc_dlp_pkg
        install_cmd $mc_dlp_pkg

        rm -rf $pkg_path/$mc_dlp_pkg
        echo "[INFO] McAfee DLP Installed"
    else
        echo "[INFO] McAfee DLP Already Installed"
    fi
}

function add_domain_admin_to_admin_group() { 
    ## Add Admin domain users and also disable itolocal + root account
    echo "[INFO] Adding domain admin to group"
    if [[ $(ls /Users | grep $ad_username) == "" ]]; then
        fancy_echo "[INFO] -------------------------- Adding Admin Domain Users -----------------------"
        while [ "$(ls /Users | grep $ad_username)" = "" ]; do
            /System/Library/CoreServices/ManagedClient.app/Contents/Resources/createmobileaccount -v -D -n \
            $ad_username -p $ad_password > /dev/null 2>&1
            dseditgroup -o edit -a $ad_username -t user admin > /dev/null 2>&1
        done
        echo "[INFO] Domain Admin Added"
    else
        echo "[INFO] Domain Admin Already Added"
    fi
}

function disable_local_users() {
    echo "[INFO] Disabling Local Users"
    localuser=$(dscl . list /Users UniqueID | awk '$2 < 1000 {print $1}' |egrep -v ^\_) > /dev/null 2>&1
    for user in $localuser; do
        if [ "$user" != "root" ] && [ "$user" != "itolocal" ]; then 
            chsh -s /usr/bin/false $user > /dev/null 2>&1
            if dseditgroup -o checkmember -m $user admin >/dev/null 2>&1; then
                dseditgroup -o edit -d $user -t user admin > /dev/null 2>&1
            fi
        fi
    done
    echo "[INFO] Local Users Disabled"
}

function add_domain_group_to_sudoer() {
    ## Update sudoers file
    echo "[INFO] Update Domain Group To Sudoer File"

    commands="Cmnd_Alias DO_COMMANDS = /sbin/route, /usr/bin/vi /etc/hosts, /usr/bin/vim \
    /etc/hosts, /usr/local/bin/brew, /usr/local/bin/npm, /usr/local/bin/yarn, /usr/local/bin/mvn, \
    /usr/local/bin/docker, /usr/local/bin/docker-machine, /usr/local/bin/node, /usr/local/bin/podman, \
    /usr/local/bin/ansible, /usr/local/bin/gem, /usr/local/bin/ruby, /usr/bin/ruby, /usr/bin/env, /usr/sbin/installer" > /dev/null 2>&1

    yes | cp /etc/sudoers /etc/sudoers.$(date +%d%m%Y) > /dev/null 2>&1
    yes | cp /etc/sudoers /tmp/sudoers > /dev/null 2>&1
    sed -i '' -e '/^Cmnd_Alias DO_COMMANDS.*/d' /tmp/sudoers
    sed -i '' -e '/^%USER\\\\Domain.*/d' /tmp/sudoers
    sed -i '' -e '/^%USER\\\\IT_HotroPC.*/d' /tmp/sudoers
    grep -q '^Cmnd_Alias DO_COMMANDS.*' /tmp/sudoers || echo $commands | tee -a /tmp/sudoers
    grep -q '^%USER\\\\Domain.*Users.*' /tmp/sudoers || echo '%USER\\Domain\ Users ALL=(ALL) NOPASSWD:SETENV: DO_COMMANDS' | tee -a /tmp/sudoers
    grep -q '^%USER\\\\Domain.*Admins.*' /tmp/sudoers || echo '%USER\\Domain\ Admins ALL=(ALL) ALL' | tee -a /tmp/sudoers > /dev/null 2>&1
    grep -q '^%USER\\\\IT_HotroPC.*' /tmp/sudoers || echo '%USER\\IT_HotroPC ALL=(ALL) ALL' | tee -a /tmp/sudoers > /dev/null 2>&1
    grep -q '^%USER\\\\IT_HotroMacOS.*' /tmp/sudoers || echo '%USER\\IT_HotroMacOS ALL=(ALL) ALL' | tee -a /tmp/sudoers > /dev/null 2>&1
    grep -q '^%USER\\\\IT_DevSecOps.*' /tmp/sudoers || echo '%USER\\IT_DevSecOps ALL=(ALL) ALL' | tee -a /tmp/sudoers > /dev/null 2>&1
    if visudo -cf /tmp/sudoers >/dev/null 2>&1; then 
        cp -f /tmp/sudoers /etc/sudoers > /dev/null 2>&1
    else
        echo "[Error] Please check sudoers syntax"
        exit 1
    fi

    echo "[INFO] Sudoer File Updated"
}

 function main() {
    ## Pre-bootstrap for Macbook Silicon
    install_rosetta2

    ## Install components
    join_domain
    install_cisco
    install_vnc
    install_intune
    install_printer
    install_webex
    install_tdoc
    install_office365
    configure_dns
    install_mcafee
add_domain_admin_to_admin_group
disable_local_users
add_domain_group_to_sudoer
 }

## -----------------------------------------------------------------------------------------##
main
