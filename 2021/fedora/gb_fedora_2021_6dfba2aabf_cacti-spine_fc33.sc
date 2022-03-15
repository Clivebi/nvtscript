if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879621" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2020-35701" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 16:51:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-20 04:53:51 +0000 (Thu, 20 May 2021)" );
	script_name( "Fedora: Security Advisory for cacti-spine (FEDORA-2021-6dfba2aabf)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6dfba2aabf" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NBKBR2MFZJ6C2I4I5PCRR6UERPY24XZN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cacti-spine'
  package(s) announced via the FEDORA-2021-6dfba2aabf advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Spine is a supplemental poller for Cacti that makes use of pthreads to achieve
excellent performance." );
	script_tag( name: "affected", value: "'cacti-spine' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "cacti-spine", rpm: "cacti-spine~1.2.17~1.fc33", rls: "FC33" ) )){
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

