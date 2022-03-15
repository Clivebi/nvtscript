if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881858" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-10 11:51:24 +0530 (Fri, 10 Jan 2014)" );
	script_cve_id( "CVE-2013-4576" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CentOS Update for gnupg CESA-2014:0016 centos5" );
	script_tag( name: "affected", value: "gnupg on CentOS 5" );
	script_tag( name: "insight", value: "The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
creating digital signatures, compliant with the proposed OpenPGP Internet
standard and the S/MIME standard.

It was found that GnuPG was vulnerable to side-channel attacks via acoustic
cryptanalysis. An attacker in close range to a target system that is
decrypting ciphertexts could possibly use this flaw to recover the RSA
secret key from that system. (CVE-2013-4576)

Red Hat would like to thank Werner Koch of GnuPG upstream for reporting
this issue. Upstream acknowledges Genkin, Shamir, and Tromer as the
original reporters.

All gnupg users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0016" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-January/020101.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnupg'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "gnupg", rpm: "gnupg~1.4.5~18.el5_10.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

