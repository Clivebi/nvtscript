if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0600.1" );
	script_cve_id( "CVE-2017-2295" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:47 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-24 13:36:00 +0000 (Thu, 24 May 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0600-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0600-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180600-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'puppet' package(s) announced via the SUSE-SU-2018:0600-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for puppet fixes the following issues:
- CVE-2017-2295: Fixed a security vulnerability where an attacker could
 force YAML deserialization in an unsafe manner, which would lead to
 remote code execution.
In default, this update would break a backwards compatibility with Puppet agents older than 3.2.2 as the SLE11 master doesn't support other fact formats than pson in default anymore. In order to allow users to continue using their SLE11 agents a patch was added that enables sending PSON from agents.
For non-SUSE clients older that 3.2.2 a new puppet master boolean option
'dangerous_fact_formats' was added. When it's set to true it enables using dangerous fact formats (e.g. YAML). When it's set to false, only PSON fact format is accepted. (bsc#1040151), (bsc#1077767)" );
	script_tag( name: "affected", value: "'puppet' package(s) on SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "puppet", rpm: "puppet~2.7.26~0.5.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "puppet-server", rpm: "puppet-server~2.7.26~0.5.3.1", rls: "SLES11.0SP4" ) )){
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

