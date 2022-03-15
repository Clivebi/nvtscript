if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1205.1" );
	script_cve_id( "CVE-2012-3515" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-11 15:21:00 +0000 (Tue, 11 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1205-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1205-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121205-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2012:1205-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kvm qemu vt100 emulation was affected by a problem where specific vt100 sequences could have been used by guest users to affect the host. (CVE-2012-3515 aka XSA-17).

Also the following non security bugs have been fixed:

 * permit qemu-kvm -device '?' even when no /dev/kvm
(bnc#772586)
 * SLES11SP2 KVM Virtio: on kvm guest, scsi inquiry was still ok on the disabled subpaths. (bnc#770153)

Security Issue reference:

 * CVE-2012-3515
>" );
	script_tag( name: "affected", value: "'kvm' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kvm", rpm: "kvm~0.15.1~0.23.1", rls: "SLES11.0SP2" ) )){
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

