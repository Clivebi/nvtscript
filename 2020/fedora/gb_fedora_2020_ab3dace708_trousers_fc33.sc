if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878565" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2020-24330", "CVE-2020-24331", "CVE-2020-24332" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-05 04:15:00 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-05 04:17:52 +0000 (Thu, 05 Nov 2020)" );
	script_name( "Fedora: Security Advisory for trousers (FEDORA-2020-ab3dace708)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-ab3dace708" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SSDL7COIFCZQMUBNAASNMKMX7W5JUHRD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'trousers'
  package(s) announced via the FEDORA-2020-ab3dace708 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "TrouSerS is an implementation of the Trusted Computing Group&#39, s Software Stack
(TSS) specification. You can use TrouSerS to write applications that make use
of your TPM hardware. TPM hardware can create, store and use RSA keys
securely (without ever being exposed in memory), verify a platform&#39, s software
state using cryptographic hashes and more." );
	script_tag( name: "affected", value: "'trousers' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "trousers", rpm: "trousers~0.3.14~4.fc33", rls: "FC33" ) )){
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

