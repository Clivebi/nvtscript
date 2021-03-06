if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869062" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-06 06:47:59 +0100 (Fri, 06 Mar 2015)" );
	script_cve_id( "CVE-2014-7818", "CVE-2014-7829", "CVE-2014-0130", "CVE-2014-0081", "CVE-2013-6414", "CVE-2013-6415", "CVE-2013-6416", "CVE-2013-6417", "CVE-2013-4491" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for rubygem-actionpack FEDORA-2014-15371" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionpack'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "rubygem-actionpack on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2014-15371" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-March/150832.html" );
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
	if(( res = isrpmvuln( pkg: "rubygem-actionpack", rpm: "rubygem-actionpack~4.0.0~5.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

