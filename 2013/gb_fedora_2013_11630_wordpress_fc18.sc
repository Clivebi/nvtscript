if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.866044" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-07-05 12:56:37 +0530 (Fri, 05 Jul 2013)" );
	script_cve_id( "CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-0235", "CVE-2013-0236", "CVE-2013-0237", "CVE-2013-2205" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Fedora Update for wordpress FEDORA-2013-11630" );
	script_xref( name: "FEDORA", value: "2013-11630" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-July/110564.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "wordpress on Fedora 18" );
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
	if(( res = isrpmvuln( pkg: "wordpress", rpm: "wordpress~3.5.2~1.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

