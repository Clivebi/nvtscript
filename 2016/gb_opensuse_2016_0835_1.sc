if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851251" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-20 06:18:10 +0100 (Sun, 20 Mar 2016)" );
	script_cve_id( "CVE-2016-2097", "CVE-2016-2098" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for rubygem-actionpack-3_2 (openSUSE-SU-2016:0835-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionpack-3_2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-actionpack-3_2 fixes the following issues:

  - CVE-2016-2097: rubygem-actionview: Possible Information Leak
  Vulnerability in Action View. (boo#968850)

  - CVE-2016-2098: rubygem-actionpack: Possible remote code execution
  vulnerability in Action Pack (boo#968849)" );
	script_tag( name: "affected", value: "rubygem-actionpack-3_2 on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0835-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-3_2", rpm: "rubygem-actionpack-3_2~3.2.17~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-3_2-doc", rpm: "rubygem-actionpack-3_2-doc~3.2.17~3.10.1", rls: "openSUSE13.2" ) )){
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

