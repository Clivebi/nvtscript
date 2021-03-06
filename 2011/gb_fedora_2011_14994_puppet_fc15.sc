if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-November/069454.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.863628" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-21 09:34:47 +0530 (Mon, 21 Nov 2011)" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2011-14994" );
	script_cve_id( "CVE-2011-3872", "CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871", "CVE-2011-3848" );
	script_name( "Fedora Update for puppet FEDORA-2011-14994" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'puppet'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC15" );
	script_tag( name: "affected", value: "puppet on Fedora 15" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
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
if(release == "FC15"){
	if(( res = isrpmvuln( pkg: "puppet", rpm: "puppet~2.6.12~1.fc15", rls: "FC15" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

