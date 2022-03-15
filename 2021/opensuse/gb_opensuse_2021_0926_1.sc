if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853889" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-34548", "CVE-2021-34549", "CVE-2021-34550" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 16:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-26 03:01:52 +0000 (Sat, 26 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for tor (openSUSE-SU-2021:0926-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0926-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GJI5DAQGLSGJLTAEBDK3BJ65DR3SJHCE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tor'
  package(s) announced via the openSUSE-SU-2021:0926-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tor fixes the following issues:

     tor 0.4.5.9

  * Don&#x27 t allow relays to spoof RELAY_END or RELAY_RESOLVED cell
       (CVE-2021-34548, boo#1187322)

  * Detect more failure conditions from the OpenSSL RNG code (boo#1187323)

  * Resist a hashtable-based CPU denial-of-service attack against relays
       (CVE-2021-34549, boo#1187324)

  * Fix an out-of-bounds memory access in v3 onion service descriptor
       parsing (CVE-2021-34550, boo#1187325)

     tor 0.4.5.8

  * allow Linux sandbox with Glibc 2.33

  * work with autoconf 2.70+

  * several other minor features and bugfixes (see announcement)

  - Fix logging issue due to systemd picking up stdout - boo#1181244
       Continue to log notices to syslog by default." );
	script_tag( name: "affected", value: "'tor' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "tor", rpm: "tor~0.4.5.9~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tor-debuginfo", rpm: "tor-debuginfo~0.4.5.9~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tor-debugsource", rpm: "tor-debugsource~0.4.5.9~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
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

