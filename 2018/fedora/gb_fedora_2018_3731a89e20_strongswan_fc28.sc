if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874617" );
	script_version( "2021-06-09T02:00:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-09 02:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-28 05:56:15 +0200 (Mon, 28 May 2018)" );
	script_cve_id( "CVE-2018-5388" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for strongswan FEDORA-2018-3731a89e20" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'strongswan'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "strongswan on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-3731a89e20" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5JNINJQPPFF4IQBGV77CRW6AHYFLYM5M" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "strongswan", rpm: "strongswan~5.6.2~6.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
