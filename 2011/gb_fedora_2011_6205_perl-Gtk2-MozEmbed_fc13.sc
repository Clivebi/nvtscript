if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-May/059706.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.863082" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2011-6205" );
	script_name( "Fedora Update for perl-Gtk2-MozEmbed FEDORA-2011-6205" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Gtk2-MozEmbed'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC13" );
	script_tag( name: "affected", value: "perl-Gtk2-MozEmbed on Fedora 13" );
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
if(release == "FC13"){
	if(( res = isrpmvuln( pkg: "perl-Gtk2-MozEmbed", rpm: "perl-Gtk2-MozEmbed~0.08~6.fc13.24", rls: "FC13" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

