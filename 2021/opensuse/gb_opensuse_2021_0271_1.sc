if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853633" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-17367", "CVE-2020-17368", "CVE-2021-26910" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-10 11:15:00 +0000 (Sun, 10 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:29 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for firejail (openSUSE-SU-2021:0271-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0271-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JJKSV64EI6OP7AKHJQVLFPJPOUXRN47F" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firejail'
  package(s) announced via the openSUSE-SU-2021:0271-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for firejail fixes the following issues:

     firejail 0.9.64.4 is shipped to openSUSE Leap 15.2

  - CVE-2021-26910: Fixed root privilege escalation due to race condition
       (boo#1181990)

     Update to 0.9.64.4:

  * disabled overlayfs, pending multiple fixes

  * fixed launch firefox for open url in telegram-desktop.profile

     Update to 0.9.64.2:

  * allow --tmpfs inside $HOME for unprivileged users

  * --disable-usertmpfs compile time option

  * allow AF_BLUETOOTH via --protocol=bluetooth

  * setup guide for new users: contrib/firejail-welcome.sh

  * implement netns in profiles

  * new profiles: spectacle, chromium-browser-privacy, gtk-straw-viewer,
       gtk-youtube-viewer, gtk2-youtube-viewer, gtk3-youtube-viewer,
       straw-viewer, lutris, dolphin-emu, authenticator-rs, servo, npm, marker,
       yarn, lsar, unar, agetpkg, mdr, shotwell, qnapi, new profiles: guvcview,
       pkglog, kdiff3, CoyIM.

     Update to version 0.9.64:

  * replaced --nowrap option with --wrap in firemon

  * The blocking action of seccomp filters has been changed from killing the
       process to returning EPERM to the caller. To get the previous behaviour,
       use --seccomp-error-action=kill or syscall:kill syntax when constructing
       filters, or override in /etc/firejail/firejail.config file.

  * Fine-grained D-Bus sandboxing with xdg-dbus-proxy. xdg-dbus-proxy must
       be installed, if not D-Bus access will be allowed. With this version
       nodbus is deprecated, in favor of dbus-user none and dbus-system none
       and will be removed in a future version.

  * DHCP client support

  * firecfg only fix dektop-files if started with sudo

  * SELinux labeling support

  * custom 32-bit seccomp filter support

  * restrict ${RUNUSER} in several profiles

  * blacklist shells such as bash in several profiles

  * whitelist globbing

  * mkdir and mkfile support for /run/user directory

  * support ignore for include

  * --include on the command line

  * splitting up media players whitelists in whitelist-players.inc

  * new condition: HAS_NOSOUND

  * new profiles: gfeeds, firefox-x11, tvbrowser, rtv, clipgrab, muraster

  * new profiles: gnome-passwordsafe, bibtex, gummi, latex, mupdf-x11-curl

  * new profiles: pdflatex, tex, wpp, wpspdf, wps, et, multimc, mupdf-x11

  * new profiles: gnome-hexgl, com.github.johnfactotum.Foliate, mupdf-gl,
       mutool

  * new profiles: desktopeditors, impressive, plan ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'firejail' package(s) on openSUSE Leap 15.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "firejail", rpm: "firejail~0.9.64.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firejail-debuginfo", rpm: "firejail-debuginfo~0.9.64.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firejail-debugsource", rpm: "firejail-debugsource~0.9.64.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

