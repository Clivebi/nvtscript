if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850856" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-10-15 12:20:18 +0200 (Thu, 15 Oct 2015)" );
	script_cve_id( "CVE-2014-0595" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for novell-qtgui (SUSE-SU-2014:0847-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'novell-qtgui'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Packages novell-ui-base and novell-qtgui were updated to prevent erroneous
  rights assignment when a user is granted 'File Scan' rights (F). In this
  case nwrights was assigning Supervisor (S) rights. (CVE-2014-0595)" );
	script_xref( name: "URL", value: "https://bugzilla.novell.com/show_bug.cgi?id=872796" );
	script_tag( name: "affected", value: "novell-qtgui, on SUSE Linux Enterprise Desktop 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:0847-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLED11\\.0SP3" );
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
if(release == "SLED11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "novell-qtgui", rpm: "novell-qtgui~3.0.0~0.20.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "novell-qtgui-cli", rpm: "novell-qtgui-cli~3.0.0~0.20.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "novell-ui-base", rpm: "novell-ui-base~3.0.0~0.10.1", rls: "SLED11.0SP3" ) )){
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

