if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-March/055650.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862897" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "FEDORA", value: "2011-2632" );
	script_cve_id( "CVE-2011-0538", "CVE-2010-3445", "CVE-2011-1143", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1138", "CVE-2011-1139", "CVE-2011-0713" );
	script_name( "Fedora Update for wireshark FEDORA-2011-2632" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC14" );
	script_tag( name: "affected", value: "wireshark on Fedora 14" );
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
if(release == "FC14"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.4.4~1.fc14", rls: "FC14" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

