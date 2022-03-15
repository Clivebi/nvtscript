if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878632" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 19:28:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-11-22 04:14:21 +0000 (Sun, 22 Nov 2020)" );
	script_name( "Fedora: Security Advisory for microcode_ctl (FEDORA-2020-2c8824c6b1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-2c8824c6b1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AQ24MFBVH3HJW3PNRQBRY4YXKC7GA57W" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the FEDORA-2020-2c8824c6b1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The microcode_ctl utility is a companion to the microcode driver written
by Tigran Aivazian <tigran(a)aivazian.fsnet.co.uk&gt, .

The microcode update is volatile and needs to be uploaded on each system
boot i.e. it doesn&#39, t reflash your cpu permanently, reboot and it reverts
back to the old microcode." );
	script_tag( name: "affected", value: "'microcode_ctl' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "microcode_ctl", rpm: "microcode_ctl~2.1~43.fc33", rls: "FC33" ) )){
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
