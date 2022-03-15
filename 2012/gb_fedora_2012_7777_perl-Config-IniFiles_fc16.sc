if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-May/080716.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864244" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-22 10:09:43 +0530 (Tue, 22 May 2012)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2012-2451" );
	script_xref( name: "FEDORA", value: "2012-7777" );
	script_name( "Fedora Update for perl-Config-IniFiles FEDORA-2012-7777" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Config-IniFiles'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "perl-Config-IniFiles on Fedora 16" );
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
if(release == "FC16"){
	if(( res = isrpmvuln( pkg: "perl-Config-IniFiles", rpm: "perl-Config-IniFiles~2.72~1.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

