if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14454.1" );
	script_cve_id( "CVE-2019-0804" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14454-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14454-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014454-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-azure-agent' package(s) announced via the SUSE-SU-2020:14454-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-azure-agent fixes the following issues:

Properly set the dhcp configuration to push the hostname to the DHCP
 server (bsc#1173866)

Do not bring the interface down to push the hostname, just use ifup

Set the hostname using hostnamectl to ensure setting is properly applied
 (bsc#1167601, bsc#1167602)

Update to version 2.2.45 (jsc#ECO-80)

Add support for Gen2 VM resource disks

Use alternate systemd detection

Fix /proc/net/route requirement that causes errors on FreeBSD

Add cloud-init auto-detect to prevent multiple provisioning mechanisms
 from relying on configuration for coordination

Disable cgroups when daemon is setup incorrectly

Remove upgrade extension loop for the same goal state

Add container id for extension telemetry events

Be more exact when detecting IMDS service health

Changing add_event to start sending missing fields" );
	script_tag( name: "affected", value: "'python-azure-agent' package(s) on SUSE Linux Enterprise Server 11." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "python-azure-agent", rpm: "python-azure-agent~2.2.45~28.8.1", rls: "SLES11.0" ) )){
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

