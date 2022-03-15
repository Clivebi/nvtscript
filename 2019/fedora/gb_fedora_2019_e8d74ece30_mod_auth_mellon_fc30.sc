if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877049" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-13038" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-28 04:15:00 +0000 (Thu, 28 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-30 03:39:01 +0000 (Sat, 30 Nov 2019)" );
	script_name( "Fedora Update for mod_auth_mellon FEDORA-2019-e8d74ece30" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-e8d74ece30" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A5E3JVHURJJNDP63CKVX5O5MJAGCQV4K" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_auth_mellon'
  package(s) announced via the FEDORA-2019-e8d74ece30 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The mod_auth_mellon module is an authentication service that implements the
SAML 2.0 federation protocol. It grants access based on the attributes
received in assertions generated by a IdP server." );
	script_tag( name: "affected", value: "'mod_auth_mellon' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "mod_auth_mellon", rpm: "mod_auth_mellon~0.15.0~1.fc30", rls: "FC30" ) )){
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

