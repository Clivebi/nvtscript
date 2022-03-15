if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1668.1" );
	script_cve_id( "CVE-2013-1923" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.2" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:33:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1668-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1668-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131668-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nfs-utils' package(s) announced via the SUSE-SU-2013:1668-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "nfs-utils receives hereby a LTSS roll-up security and bugfix update.

 * CVE-2013-1923: Allow DNS lookups to be avoided when determining kerberos identity of server. The NFS_GSSD_AVOID_DNS sysconfig variable must to be set for this to take full effect as some installations could be negatively affected by this change

More bugs have been fixed:

 * Fixed bugs with the info provided by 'showmount -e'
not being updated correctly. (bnc#661493)
 * nfsserver.init: Fix initialization of
/var/lib/nfs/state and run sm-notify at start up time when necessary (bnc#628887)
 * Increase number of supported krb5 mounts from 32 to 256. (bnc#716463)
 * Avoid crash if krb5_init_context fails (bnc#806840)

Security Issue reference:

 * CVE-2013-1923
>" );
	script_tag( name: "affected", value: "'nfs-utils' package(s) on SUSE Linux Enterprise Server 10 SP3." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "nfs-utils", rpm: "nfs-utils~1.0.7~36.39.42.1", rls: "SLES10.0SP3" ) )){
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

