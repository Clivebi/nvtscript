if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850409" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-03-11 18:29:15 +0530 (Mon, 11 Mar 2013)" );
	script_cve_id( "CVE-2013-0640", "CVE-2013-0641" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2013:0335-1" );
	script_name( "openSUSE: Security Advisory for acroread (openSUSE-SU-2013:0335-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'acroread'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.1" );
	script_tag( name: "affected", value: "acroread on openSUSE 12.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "acroread was updated to 9.5.4 to fix remote code execution
  problems. (CVE-2013-0640, CVE-2013-0641)

  More information can be found at the linked references." );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2013-02/msg00021.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-07.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
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
report = "";
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "acroread-cmaps", rpm: "acroread-cmaps~9.4.1~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread-fonts-ja", rpm: "acroread-fonts-ja~9.4.1~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread-fonts-ko", rpm: "acroread-fonts-ko~9.4.1~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread-fonts-zh_CN", rpm: "acroread-fonts-zh_CN~9.4.1~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread-fonts-zh_TW", rpm: "acroread-fonts-zh_TW~9.4.1~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread", rpm: "acroread~9.5.4~3.17.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "acroread-browser-plugin", rpm: "acroread-browser-plugin~9.5.4~3.17.1", rls: "openSUSE12.1" ) )){
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

