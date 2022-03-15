if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879182" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-20179" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 01:58:00 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-20 04:08:23 +0000 (Sat, 20 Mar 2021)" );
	script_name( "Fedora: Security Advisory for pki-core (FEDORA-2021-6c412a4601)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6c412a4601" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DDOLFOLEIV7I4EUC3SCZBXL6E2ER7ZEN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pki-core'
  package(s) announced via the FEDORA-2021-6c412a4601 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Dogtag PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Automatic Certificate Management Environment (ACME) Responder

  * Certificate Authority (CA)

  * Key Recovery Authority (KRA)

  * Online Certificate Status Protocol (OCSP) Manager

  * Token Key Service (TKS)

  * Token Processing Service (TPS)" );
	script_tag( name: "affected", value: "'pki-core' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "pki-core", rpm: "pki-core~10.10.5~5.fc33", rls: "FC33" ) )){
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

