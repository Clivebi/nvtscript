if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-August/085694.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864651" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 10:23:53 +0530 (Thu, 30 Aug 2012)" );
	script_cve_id( "CVE-2012-4285", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4296", "CVE-2012-4297", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4290" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2012-12091" );
	script_name( "Fedora Update for wireshark FEDORA-2012-12091" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "wireshark on Fedora 17" );
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
if(release == "FC17"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.6.10~1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

