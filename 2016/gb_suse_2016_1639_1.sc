if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851348" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-06-22 05:29:12 +0200 (Wed, 22 Jun 2016)" );
	script_cve_id( "CVE-2016-5104" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for libimobiledevice (SUSE-SU-2016:1639-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libimobiledevice'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libimobiledevice, usbmuxd were updated to fix one security issue.

  This security issue was fixed:

  - CVE-2016-5104: Sockets listening on INADDR_ANY instead of only locally
  (982014)." );
	script_tag( name: "affected", value: "libimobiledevice, on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2016:1639-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLED12\\.0SP0|SLES12\\.0SP0)" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice-debugsource", rpm: "libimobiledevice-debugsource~1.1.5~6.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice-tools", rpm: "libimobiledevice-tools~1.1.5~6.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice-tools-debuginfo", rpm: "libimobiledevice-tools-debuginfo~1.1.5~6.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice4", rpm: "libimobiledevice4~1.1.5~6.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice4-debuginfo", rpm: "libimobiledevice4-debuginfo~1.1.5~6.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libusbmuxd2", rpm: "libusbmuxd2~1.0.8~12.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libusbmuxd2-debuginfo", rpm: "libusbmuxd2-debuginfo~1.0.8~12.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd", rpm: "usbmuxd~1.0.8~12.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd-debuginfo", rpm: "usbmuxd-debuginfo~1.0.8~12.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd-debugsource", rpm: "usbmuxd-debugsource~1.0.8~12.1", rls: "SLED12.0SP0" ) )){
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice-debugsource", rpm: "libimobiledevice-debugsource~1.1.5~6.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice4", rpm: "libimobiledevice4~1.1.5~6.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libimobiledevice4-debuginfo", rpm: "libimobiledevice4-debuginfo~1.1.5~6.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libusbmuxd2", rpm: "libusbmuxd2~1.0.8~12.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libusbmuxd2-debuginfo", rpm: "libusbmuxd2-debuginfo~1.0.8~12.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd", rpm: "usbmuxd~1.0.8~12.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd-debuginfo", rpm: "usbmuxd-debuginfo~1.0.8~12.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usbmuxd-debugsource", rpm: "usbmuxd-debugsource~1.0.8~12.1", rls: "SLES12.0SP0" ) )){
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

