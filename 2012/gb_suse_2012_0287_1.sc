if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850256" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 23:01:29 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2012-0791" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "openSUSE-SU", value: "2012:0287-1" );
	script_name( "openSUSE: Security Advisory for horde (openSUSE-SU-2012:0287-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'horde'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	script_tag( name: "affected", value: "horde on openSUSE 11.4" );
	script_tag( name: "insight", value: "This version upgrade of horde3-dimp to 4.3.11 fixes several
  issues (including security related flaws, CVE-2012-0791)
  and adds new features." );
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
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "horde3-dimp", rpm: "horde3-dimp~1.1.8~0.3.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "horde3-imp", rpm: "horde3-imp~4.3.11~0.3.1", rls: "openSUSE11.4" ) )){
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

