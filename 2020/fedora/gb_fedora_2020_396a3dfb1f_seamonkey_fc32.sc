if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878636" );
	script_version( "2020-11-27T03:36:52+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-27 03:36:52 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-22 04:14:39 +0000 (Sun, 22 Nov 2020)" );
	script_name( "Fedora: Security Advisory for seamonkey (FEDORA-2020-396a3dfb1f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-396a3dfb1f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/G3XWCIHS7U34LGOVL4XNZEGSDL4G7JM5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the FEDORA-2020-396a3dfb1f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "SeaMonkey is an all-in-one Internet application suite (previously made
popular by Netscape and Mozilla). It includes an Internet browser,
advanced e-mail, newsgroup and feed client, a calendar, IRC client,
HTML editor and a tool to inspect the DOM for web pages. It is derived
from the application formerly known as Mozilla Application Suite." );
	script_tag( name: "affected", value: "'seamonkey' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~2.53.5~2.fc32", rls: "FC32" ) )){
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
