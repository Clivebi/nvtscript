if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875718" );
	script_version( "2019-05-14T05:04:40+0000" );
	script_cve_id( "CVE-2004-2687" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-05-14 05:04:40 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:17:29 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for distcc FEDORA-2019-dfef0af227" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-dfef0af227" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HVNNJILIKIJXNXL7OUGI6FUPAEVLPUDA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'distcc'
  package(s) announced via the FEDORA-2019-dfef0af227 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "distcc is a program to distribute compilation of C or C++ code across
several machines on a network. distcc should always generate the same
results as a local compile, is simple to install and use, and is often
two or more times faster than a local compile." );
	script_tag( name: "affected", value: "'distcc' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "distcc", rpm: "distcc~3.2rc1~22.fc29", rls: "FC29" ) )){
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

