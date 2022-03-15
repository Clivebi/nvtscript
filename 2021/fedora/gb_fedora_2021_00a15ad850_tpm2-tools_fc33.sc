if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879792" );
	script_version( "2021-08-24T06:00:58+0000" );
	script_cve_id( "CVE-2021-3565" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 05:15:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 03:18:33 +0000 (Tue, 06 Jul 2021)" );
	script_name( "Fedora: Security Advisory for tpm2-tools (FEDORA-2021-00a15ad850)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-00a15ad850" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ESY6HRYUKR5ZG2K5QAJQC5S6HMKZMFK7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tpm2-tools'
  package(s) announced via the FEDORA-2021-00a15ad850 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "tpm2-tools is a batch of tools for tpm2.0. It is based on tpm2-tss." );
	script_tag( name: "affected", value: "'tpm2-tools' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "tpm2-tools", rpm: "tpm2-tools~4.3.2~1.fc33", rls: "FC33" ) )){
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

