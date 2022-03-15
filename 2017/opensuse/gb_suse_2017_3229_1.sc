if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851659" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-07 07:41:40 +0100 (Thu, 07 Dec 2017)" );
	script_cve_id( "CVE-2017-16852" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for shibboleth-sp (openSUSE-SU-2017:3229-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shibboleth-sp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for shibboleth-sp fixes the following issues:

  Security issue fixed:

  - CVE-2017-16852: Fix critical security checks in the Dynamic
  MetadataProvider plugin in Shibboleth Service (bsc#1068689).

  This update was imported from the SUSE:SLE-12-SP1:Update update project." );
	script_tag( name: "affected", value: "shibboleth-sp on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3229-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite6", rpm: "libshibsp-lite6~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite6-debuginfo", rpm: "libshibsp-lite6-debuginfo~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp6", rpm: "libshibsp6~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp6-debuginfo", rpm: "libshibsp6-debuginfo~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp", rpm: "shibboleth-sp~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debuginfo", rpm: "shibboleth-sp-debuginfo~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debugsource", rpm: "shibboleth-sp-debugsource~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-devel", rpm: "shibboleth-sp-devel~2.5.5~6.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite6", rpm: "libshibsp-lite6~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite6-debuginfo", rpm: "libshibsp-lite6-debuginfo~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp6", rpm: "libshibsp6~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp6-debuginfo", rpm: "libshibsp6-debuginfo~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp", rpm: "shibboleth-sp~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debuginfo", rpm: "shibboleth-sp-debuginfo~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debugsource", rpm: "shibboleth-sp-debugsource~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-devel", rpm: "shibboleth-sp-devel~2.5.5~9.2", rls: "openSUSELeap42.3" ) )){
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

