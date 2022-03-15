if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865630" );
	script_version( "2021-02-05T10:24:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-05 10:24:35 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "creation_date", value: "2013-05-23 09:53:31 +0530 (Thu, 23 May 2013)" );
	script_cve_id( "CVE-2002-2443", "CVE-2013-1416", "CVE-2012-1016", "CVE-2013-1415" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Fedora Update for krb5 FEDORA-2013-8212" );
	script_xref( name: "FEDORA", value: "2013-8212" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105879.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "krb5 on Fedora 18" );
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
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.10.3~17.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

