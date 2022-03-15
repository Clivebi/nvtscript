if(description){
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2012-12/msg00009.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.850430" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-03-11 18:29:46 +0530 (Mon, 11 Mar 2013)" );
	script_cve_id( "CVE-2012-4559", "CVE-2012-4560", "CVE-2012-4561", "CVE-2012-4562" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:1620-1" );
	script_name( "openSUSE: Security Advisory for update (openSUSE-SU-2012:1620-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.2" );
	script_tag( name: "affected", value: "update on openSUSE 12.2" );
	script_tag( name: "insight", value: "This update of libssh fixed various memory management
  issues that could have security implications (Code
  execution, Denial of Service)." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
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
if(release == "openSUSE12.2"){
	if(!isnull( res = isrpmvuln( pkg: "libssh-debugsource", rpm: "libssh-debugsource~0.5.2~2.4.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh-devel", rpm: "libssh-devel~0.5.2~2.4.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh-devel-doc", rpm: "libssh-devel-doc~0.5.2~2.4.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh4", rpm: "libssh4~0.5.2~2.4.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh4-debuginfo", rpm: "libssh4-debuginfo~0.5.2~2.4.1", rls: "openSUSE12.2" ) )){
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

