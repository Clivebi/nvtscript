if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852104" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-14526" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-28 06:04:13 +0100 (Sun, 28 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for wpa_supplicant (openSUSE-SU-2018:3539-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3539-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00083.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the openSUSE-SU-2018:3539-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wpa_supplicant provides the following fixes:

  This security issue was fixed:

  - CVE-2018-14526: Under certain conditions, the integrity of EAPOL-Key
  messages was not checked, leading to a decryption oracle. An attacker
  within range of the Access Point and client could have abused the
  vulnerability to recover sensitive information (bsc#1104205)

  These non-security issues were fixed:

  - Fix reading private key passwords from the configuration file.
  (bsc#1099835)

  - Enable PWD as EAP method. This allows for password-based authentication,
  which is easier to setup than most of the other methods, and is used by
  the Eduroam network. (bsc#1109209)

  - compile eapol_test binary to allow testing via radius proxy and server
  (note: this does not match CONFIG_EAPOL_TEST which sets -Werror and
  activates an assert call inside the code of wpa_supplicant)
  (bsc#1111873), (fate#326725)

  - Enabled timestamps in log file when being invoked by systemd service
  file (bsc#1080798).

  - Fixes the default file permissions of the debug log file to more sane
  values, i.e. it is no longer world-readable (bsc#1098854).

  - Open the debug log file with O_CLOEXEC, which will prevent file
  descriptor leaking to child processes (bsc#1098854).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1316=1" );
	script_tag( name: "affected", value: "wpa_supplicant on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.6~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debuginfo", rpm: "wpa_supplicant-debuginfo~2.6~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debugsource", rpm: "wpa_supplicant-debugsource~2.6~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui", rpm: "wpa_supplicant-gui~2.6~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui-debuginfo", rpm: "wpa_supplicant-gui-debuginfo~2.6~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
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

