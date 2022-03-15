if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869126" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-27 06:46:43 +0100 (Fri, 27 Mar 2015)" );
	script_cve_id( "CVE-2011-2895", "CVE-2011-4028", "CVE-2013-4396", "CVE-2013-6462", "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211", "CVE-2014-8092", "CVE-2014-8097", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8102", "CVE-2014-8101", "CVE-2014-8093", "CVE-2014-8098", "CVE-2015-0255" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for nx-libs FEDORA-2015-3964" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nx-libs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "nx-libs on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-3964" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-March/152878.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "nx-libs", rpm: "nx-libs~3.5.0.29~1.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

