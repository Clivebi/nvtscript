if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:133" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831722" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-17 10:23:08 +0530 (Fri, 17 Aug 2012)" );
	script_cve_id( "CVE-2012-0065" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:133" );
	script_name( "Mandriva Update for usbmuxd MDVSA-2012:133 (usbmuxd)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'usbmuxd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "usbmuxd on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that usbmuxd did not correctly perform bounds
  checking when processing the SerialNumber field of USB devices. An
  attacker with physical access could use this to crash usbmuxd
  or potentially execute arbitrary code as the 'usbmux' user
  (CVE-2012-0065).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "libusbmuxd1", rpm: "libusbmuxd1~1.0.7~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libusbmuxd-devel", rpm: "libusbmuxd-devel~1.0.7~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "usbmuxd", rpm: "usbmuxd~1.0.7~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64usbmuxd1", rpm: "lib64usbmuxd1~1.0.7~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64usbmuxd-devel", rpm: "lib64usbmuxd-devel~1.0.7~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
