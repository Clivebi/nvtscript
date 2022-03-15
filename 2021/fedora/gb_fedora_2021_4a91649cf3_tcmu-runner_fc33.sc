if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878880" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-28374" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-15 22:04:00 +0000 (Mon, 15 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-04 04:05:11 +0000 (Thu, 04 Feb 2021)" );
	script_name( "Fedora: Security Advisory for tcmu-runner (FEDORA-2021-4a91649cf3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-4a91649cf3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HK7SRTITN5ABAUOOIGFVR7XE5YKYYAVO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tcmu-runner'
  package(s) announced via the FEDORA-2021-4a91649cf3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A daemon that handles the complexity of the LIO kernel target&#39, s userspace
passthrough interface (TCMU). It presents a C plugin API for extension modules
that handle SCSI requests in ways not possible or suitable to be handled
by LIO&#39, s in-kernel backstores." );
	script_tag( name: "affected", value: "'tcmu-runner' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner", rpm: "tcmu-runner~1.5.2~7.fc33", rls: "FC33" ) )){
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

