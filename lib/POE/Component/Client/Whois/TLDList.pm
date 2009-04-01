package POE::Component::Client::Whois::TLDList;

use strict;
use warnings;
use Data::Dumper;
use vars qw($VERSION);

$VERSION = '1.17';

my %data = (
                             '.cy' => [
                                        'NONE',
                                        '#',
                                        'www.nic.cy'
                                      ],
                             '.su' => [
                                        'whois.ripn.net'
                                      ],
                             '.nz' => [
                                        'whois.domainz.net.nz'
                                      ],
                             '.in' => [
                                        'whois.ncst.ernet.in'
                                      ],
                             '.ni' => [
                                        'NONE',
                                        '#',
                                        'www.nic.ni'
                                      ],
                             '.la' => [
                                        'whois.nic.la'
                                      ],
                             '.co.za' => [
                                           'WEB',
                                           'http://whois.co.za/'
                                         ],
                             '.sv' => [
                                        'WEB',
                                        'http://www.uca.edu.sv/dns/',
                                        '#',
                                        'http://www.svnet.org.sv/'
                                      ],
                             '.pm' => [
                                        'whois.nic.fr'
                                      ],
                             '.ar' => [
                                        'WEB',
                                        'http://www.nic.ar/consultas/consdom.htm'
                                      ],
                             '.ng' => [
                                        'whois.rg.net'
                                      ],
                             '.ae' => [
                                        'WEB',
                                        'http://cc.emirates.net.ae/Customer_care/cc_card/check_domains.choose_domains/'
                                      ],
                             '-nicat' => [
                                           'whois.nic.at'
                                         ],
                             '.tt' => [
                                        'WEB',
                                        'http://www.nic.tt/cgi-bin/whois.cgi'
                                      ],
                             '-dk' => [
                                        'whois.dk-hostmaster.dk'
                                      ],
                             '.mp' => [
                                        'NONE',
                                        '#',
                                        'www.marketplace.mp'
                                      ],
                             '.info' => [
                                          'whois.afilias.info'
                                        ],
                             '.ws' => [
                                        'whois.samoanic.ws'
                                      ],
                             '.gov.uk' => [
                                            'whois.ja.net'
                                          ],
                             '.pw' => [
                                        'whois.nic.pw'
                                      ],
                             '.no.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.au' => [
                                        'whois.aunic.net'
                                      ],
                             '.je' => [
                                        'NONE',
                                        '#',
                                        'http://www.isles.net'
                                      ],
                             '.gr' => [
                                        'WEB',
                                        'http://www.hostmaster.gr/cgi-bin/webwhois'
                                      ],
                             '.az' => [
                                        'NONE',
                                        '#',
                                        'www.nic.az'
                                      ],
                             '.se.net' => [
                                            'whois.centralnic.net'
                                          ],
                             '.uk.net' => [
                                            'whois.centralnic.net'
                                          ],
                             '.vi' => [
                                        'WEB',
                                        'http://208.30.96.227/whoisform.htm'
                                      ],
                             '.ad' => [
                                        'NONE',
                                        '#',
                                        'www.nic.ad'
                                      ],
                             '-arin' => [
                                          'whois.arin.net'
                                        ],
                             '.ua' => [
                                        'whois.com.ua'
                                      ],
                             '.gov' => [
                                         'whois.nic.gov'
                                       ],
                             '.lk' => [
                                        'whois.nic.lk'
                                      ],
                             '.do' => [
                                        'WEB',
                                        'http://www.nic.do'
                                      ],
                             '.ls' => [
                                        'NONE'
                                      ],
                             '.tw' => [
                                        'whois.twnic.net'
                                      ],
                             '.nc' => [
                                        'whois.cctld.nc'
                                      ],
                             '.sk' => [
                                        'whois.ripe.net'
                                      ],
                             '.bm' => [
                                        'WEB',
                                        'http://www.bermudanic.bm/cgi-bin/BermudaNIC/rwhois_query.pl',
                                        '#',
                                        'rwhois.bermudanic.bm:4321'
                                      ],
                             '-norid' => [
                                           'whois.norid.no'
                                         ],
                             '.gg' => [
                                        'NONE',
                                        '#',
                                        'http://www.isles.net'
                                      ],
                             '.cd' => [
                                        'whois.nic.cd'
                                      ],
                             '.lv' => [
                                        'whois.ripe.net'
                                      ],
                             '.kg' => [
                                        'whois.domain.kg'
                                      ],
                             '.fk' => [
                                        'NONE',
                                        '#',
                                        'http://www.fidc.org.fk/domain-registration/home.htm'
                                      ],
                             '.vc' => [
                                        'whois.opensrs.net'
                                      ],
                             '.so' => [
                                        'NONE',
                                        '#',
                                        'www.nic.so',
                                        '-',
                                        'no',
                                        'country,',
                                        'no',
                                        'NIC'
                                      ],
                             '.an' => [
                                        'NONE',
                                        '#',
                                        'http://www.una.net/an_domreg/'
                                      ],
                             '.sh' => [
                                        'whois.nic.sh'
                                      ],
                             '.ee' => [
                                        'whois.eenet.ee'
                                      ],
                             '.pg' => [
                                        'NONE',
                                        '#',
                                        'http://www.unitech.ac.pg/Unitech_General/ITS/ITS_Dns.htm'
                                      ],
                             '.md' => [
                                        'WEB',
                                        'http://www.nic.md/search.html'
                                      ],
                             '.bs' => [
                                        'WEB',
                                        'http://www.nic.bs/cgi-bin/search.pl'
                                      ],
                             '.ac.za' => [
                                           'whois.ac.za'
                                         ],
                             '.fo' => [
                                        'whois.ripe.net',
                                        '#',
                                        'www.nic.fo'
                                      ],
                             '.uk.co' => [
                                           'whois.uk.co'
                                         ],
                             '.us' => [
                                        'NONE',
                                        '#',
                                        'for',
                                        'info:',
                                        'usdomreg@nic.us'
                                      ],
                             '.cn' => [
                                        'whois.cnnic.net.cn'
                                      ],
                             '.tp' => [
                                        'NONE',
                                        '#',
                                        'www.nic.tp'
                                      ],
                             '.bz' => [
                                        'NONE',
                                        '#',
                                        'www.nic.nz'
                                      ],
                             '.tm' => [
                                        'whois.nic.tm'
                                      ],
                             '.zm' => [
                                        'NONE',
                                        '#',
                                        'http://www.zamnet.zm/domain.shtml'
                                      ],
			     '.eu' => [
					'whois.eu'
				      ],
                             '.br.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.eu.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.biz' => [
                                         'whois.nic.biz'
                                       ],
                             '-au-dom' => [
                                            'whois.aunic.net'
                                          ],
                             '.qc.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.ai' => [
                                        'NONE',
                                        '#',
                                        'http://www.offshore.com.ai/domain_names/'
                                      ],
                             '-metu' => [
                                          'whois.metu.edu.tr'
                                        ],
                             '.rw' => [
                                        'WEB',
                                        'http://www.nic.rw/cgi-bin/whoisrw.pl'
                                      ],
                             '.mo' => [
                                        'WEB',
                                        'http://www.monic.net.mo',
                                        '#',
                                        'whois.umac.mo'
                                      ],
                             '.nu' => [
                                        'whois.nic.nu'
                                      ],
                             '.yu' => [
                                        'NONE',
                                        '#',
                                        'www.nic.yu'
                                      ],
                             '.pro' => [
                                         'whois.nic.pro'
                                       ],
                             '.aq' => [
                                        'NONE',
                                        '#',
                                        '2day.com'
                                      ],
                             '.com' => [
                                         'whois.internic.net'
                                       ],
                             '.dj' => [
                                        'NONE',
                                        '#',
                                        'www.nic.dj',
                                        '(NOT',
                                        'YET)'
                                      ],
                             '-itnic' => [
                                           'whois.nic.it'
                                         ],
                             '.na' => [
                                        'WEB',
                                        'http://www.lisse.na/cgi-bin/whois.cgi'
                                      ],
                             '.vu' => [
                                        'WEB',
                                        'http://www.vunic.vu/whois'
                                      ],
                             '.st' => [
                                        'whois.nic.st'
                                      ],
                             '.sz' => [
                                        'NONE',
                                        '#',
                                        'http://www.iafrica.sz/domreg/'
                                      ],
                             '.aero' => [
                                          'whois.nic.aero'
                                        ],
                             '.coop' => [
                                          'whois.nic.coop'
                                        ],
                             '.ps' => [
                                        'WEB',
                                        'http://www.nic.ps/whois/'
                                      ],
                             '.ms' => [
                                        'whois.adamsnames.tc'
                                      ],
                             '.be' => [
                                        'whois.dns.be'
                                      ],
                             '.pa' => [
                                        'WEB',
                                        'http://www.nic.pa'
                                      ],
                             '.ac.cn' => [
                                           'whois.cnc.ac.cn'
                                         ],
                             '.fj' => [
                                        'whois.usp.ac.fj'
                                      ],
                             '.th' => [
                                        'whois.thnic.net'
                                      ],
                             '-hst' => [
                                         'whois.networksolutions.com'
                                       ],
                             '.name' => [
                                          'whois.nic.name'
                                        ],
                             '.hr' => [
                                        'WEB',
                                        'http://noc.srce.hr/web-eng/searchdomain.htm'
                                      ],
                             '.cz' => [
                                        'whois.nic.cz'
                                      ],
                             '.gi' => [
                                        'NONE',
                                        '#',
                                        'http://www.gibnet.gi/nic/'
                                      ],
                             '.tg' => [
                                        'WEB',
                                        'http://www.nic.tg'
                                      ],
                             '.lu' => [
                                        'whois.restena.lu'
                                      ],
                             '.cc' => [
                                        'whois.nic.cc'
                                      ],
                             '-ripn' => [
                                          'whois.ripn.net'
                                        ],
                             '.tv' => [
                                        'NONE',
                                        '#',
                                        'http://internet.tv'
                                      ],
                             '.ao' => [
                                        'NONE',
                                        '#',
                                        'www.dns.ao'
                                      ],
                             '.mu' => [
                                        'WEB',
                                        'http://www.nic.mu/cgi-bin/mu_whois.cgi'
                                      ],
                             '.za.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.bd' => [
                                        'NONE',
                                        '#',
                                        'NIC?'
                                      ],
                             '.mn' => [
                                        'WEB',
                                        'http://whois.nic.mn'
                                      ],
                             '.hn' => [
                                        'NONE',
                                        '#',
                                        'www.nic.hn'
                                      ],
                             '.pr' => [
                                        'NONE',
                                        '#',
                                        'http://www.uprr.pr/main.html'
                                      ],
                             '-cn' => [
                                        'whois.cnnic.net.cn'
                                      ],
                             '.by' => [
                                        'WEB',
                                        'http://www.tld.by/indexeng.html'
                                      ],
                             '-sgnic' => [
                                           'whois.nic.net.sg'
                                         ],
                             '.it' => [
                                        'whois.nic.it'
                                      ],
                             '.um' => [
                                        'NONE',
                                        '#',
                                        'see',
                                        '.us'
                                      ],
                             '.ch' => [
                                        'whois.nic.ch'
                                      ],
                             '.cm' => [
                                        'NONE',
                                        '#',
                                        'http://info.intelcam.cm'
                                      ],
                             '.al' => [
                                        'NONE',
                                        '#',
                                        'http://www.inima.al/Domains.html'
                                      ],
                             '.mr' => [
                                        'NONE',
                                        '#',
                                        'http://www.univ-nkc.mr/nic_mr.html'
                                      ],
                             '.ci' => [
                                        'www.nic.ci'
                                      ],
                             '.gl' => [
                                        'whois.ripe.net'
                                      ],
                             '.lr' => [
                                        'NONE',
                                        '#',
                                        'http://www.psg.com/dns/lr/'
                                      ],
                             '.bt' => [
                                        'whois.nic.tm'
                                      ],
                             '-mnt' => [
                                         'whois.ripe.net'
                                       ],
                             '.tn' => [
                                        'NONE',
                                        '#',
                                        'http://www.ati.tn/Nic/'
                                      ],
                             '.im' => [
                                        'WEB',
                                        'http://www.nic.im/exist.html'
                                      ],
                             '.cl' => [
                                        'whois.nic.cl'
                                      ],
                             '.ly' => [
                                        'WEB',
                                        'http://www.lydomains.com/whois.asp'
                                      ],
                             '.gu' => [
                                        'WEB',
                                        'http://gadao.gov.gu/Scripts/wwsquery/wwsquery.dll?hois=guamquery'
                                      ],
                             '.fed.us' => [
                                            'whois.nic.gov'
                                          ],
                             '.sj' => [
                                        'NONE',
                                        '#',
                                        'http://www.uninett.no/navn/bv-sj.html'
                                      ],
                             '-frnic' => [
                                           'whois.nic.fr'
                                         ],
                             '.edu' => [
                                         'whois.educause.net'
                                       ],
                             '-org' => [
                                         'whois.networksolutions.com'
                                       ],
                             '.cx' => [
                                        'whois.nic.cx'
                                      ],
                             '.kh' => [
                                        'NONE',
                                        '#',
                                        'http://www.mptc.gov.kh/Reculation/DNS.htm'
                                      ],
                             '.mil' => [
                                         'whois.nic.mil'
                                       ],
                             '.dz' => [
                                        'NONE'
                                      ],
                             '.ru' => [
                                        'whois.ripn.net'
                                      ],
                             '.ug' => [
                                        'www.registry.co.ug'
                                      ],
                             '.kz' => [
                                        'whois.domain.kz'
                                      ],
                             '.mg' => [
                                        'NONE',
                                        '#',
                                        'www.nic.mg'
                                      ],
                             '.int' => [
                                         'whois.icann.org'
                                       ],
                             '.ba' => [
                                        'NONE',
                                        '#',
                                        'http://www.utic.net.ba/domen/'
                                      ],
                             '.km' => [
                                        'NONE',
                                        '#',
                                        'NO',
                                        'NIC'
                                      ],
                             '.sr' => [
                                        'whois.register.sr'
                                      ],
                             '.vg' => [
                                        'whois.adamsnames.tc'
                                      ],
                             '-dom' => [
                                         'whois.networksolutions.com'
                                       ],
                             '.tc' => [
                                        'whois.adamsnames.tc'
                                      ],
                             '.tz' => [
                                        'NONE',
                                        '#',
                                        'http://www.psg.com/dns/tz/'
                                      ],
                             '.at' => [
                                        'whois.aco.net'
                                      ],
                             '.bg' => [
                                        'whois.ripe.net'
                                      ],
                             '.lb' => [
                                        'WEB',
                                        'http://www.aub.edu.lb/lbdr/search.html'
                                      ],
                             '.mc' => [
                                        'whois.ripe.net'
                                      ],
                             '.tr' => [
                                        'whois.metu.edu.tr'
                                      ],
                             '.co' => [
                                        'WEB',
                                        'http://daimon.uniandes.edu.co:8890/dominio/plsql/PConsulta.ConsultarDominio'
                                      ],
                             '.mx' => [
                                        'whois.nic.mx'
                                      ],
                             '.es' => [
                                        'WEB',
                                        'http://www.nic.es/whois/'
                                      ],
                             '.fi' => [
                                        'WEB',
                                        'http://cgi.ficora.fi/wwwbin/domains.pl?language=eng'
                                      ],
                             '.ve' => [
                                        'WEB',
                                        'http://www.nic.ve/nicwho01.html',
                                        '#',
                                        'rwhois.reacciun.ve:4321'
                                      ],
                             '.org' => [
                                         'whois.publicinterestregistry.net'
                                       ],
                             '.sn' => [
                                        'NONE',
                                        '#',
                                        'www.nic.sn'
                                      ],
                             '.sc' => [
                                        'NONE',
                                        '#',
                                        'www.nic.sc'
                                      ],
                             '.uk.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.bo' => [
                                        'NONE',
                                        '#',
                                        'www.nic.bo'
                                      ],
                             '.ec' => [
                                        'WEB',
                                        'http://www.nic.ec'
                                      ],
                             '.qa' => [
                                        'NONE',
                                        '#',
                                        'http://www.qatar.net.qa/services/virtual.htm'
                                      ],
                             '.dk' => [
                                        'WEB',
                                        'http://www.dk-hostmaster.dk/dkwhois.php?lang=eng'
                                      ],
                             '.cn.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.kw' => [
                                        'WEB',
                                        'http://www.domainname.net.kw'
                                      ],
                             '.tk' => [
                                        'NONE',
                                        '#',
                                        '2day.com'
                                      ],
                             '.va' => [
                                        'whois.ripe.net'
                                      ],
                             '.kr' => [
                                        'whois.krnic.net'
                                      ],
                             '.vn' => [
                                        'WEB',
                                        'http://www.vnnic.net.vn/english/reg_domain/'
                                      ],
                             '.net' => [
                                         'whois.internic.net'
                                       ],
                             '.pn' => [
                                        'NONE',
                                        '#',
                                        'www.nic.pn'
                                      ],
                             '.cg' => [
                                        'WEB',
                                        'http://www.nic.cg/cgi-bin/whoiscg.pl'
                                      ],
                             '.hk' => [
                                        'whois.hkdnr.net.hk'
                                      ],
                             '.mm' => [
                                        'whois.nic.mm'
                                      ],
                             '.ro' => [
                                        'whois.rotld.ro'
                                      ],
                             '.gm' => [
                                        'whois.ripe.net',
                                        '#',
                                        'www.nic.gm'
                                      ],
                             '.sg' => [
                                        'whois.nic.net.sg'
                                      ],
                             '-lrms' => [
                                          'whois.afilias.net'
                                        ],
                             '.ck' => [
                                        'whois.nic.ck'
                                      ],
                             '.ac' => [
                                        'whois.nic.ac'
                                      ],
                             '.zr' => [
                                        'NONE',
                                        '#',
                                        'obsoleted',
                                        'by',
                                        'cd'
                                      ],
                             '.fm' => [
                                        'WEB',
                                        'http://www.nic.fm/register.html'
                                      ],
                             '.gb.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.py' => [
                                        'WEB',
                                        'http://www.nic.py/consultas/'
                                      ],
                             '.tf' => [
                                        'whois.adamsnames.tc'
                                      ],
                             '.net.au' => [
                                            'whois.connect.com.au'
                                          ],
                             '.ke' => [
                                        'NONE',
                                        '#',
                                        'http://www.nbnet.co.ke/domain.htm'
                                      ],
                             '.ca' => [
                                        'whois.cira.ca'
                                      ],
                             '.za' => [
                                        'NONE',
                                        '#',
                                        'http://www2.frd.ac.za/uninet/zadomains.html'
                                      ],
                             '.ge' => [
                                        'WEB',
                                        'http://www.nic.net.ge'
                                      ],
                             '.jp' => [
                                        'whois.nic.ad.jp'
                                      ],
                             '.id' => [
                                        'whois.idnic.net.id'
                                      ],
                             '.bb' => [
                                        'WEB',
                                        'http://domains.org.bb/regsearch/'
                                      ],
                             '-tw' => [
                                        'whois.twnic.net'
                                      ],
                             '.hu.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.tj' => [
                                        'whois.nic.tj'
                                      ],
                             '.cu' => [
                                        'WEB',
                                        'http://www.nic.cu/consultas/consult.html'
                                      ],
                             '-il' => [
                                        'whois.isoc.org.il'
                                      ],
                             '.gt' => [
                                        'WEB',
                                        'http://www.gt/whois.htm'
                                      ],
                             '.gb' => [
                                        'NONE'
                                      ],
                             '.fr' => [
                                        'whois.nic.fr'
                                      ],
                             '.gb.net' => [
                                            'whois.centralnic.net'
                                          ],
                             '.ky' => [
                                        'NONE',
                                        '#',
                                        'www.nic.ky'
                                      ],
                             '.bv' => [
                                        'NONE',
                                        '#',
                                        'http://www.uninett.no/navn/bv-sj.html'
                                      ],
                             '.mw' => [
                                        'WEB',
                                        'http://www.tarsus.net/whois/'
                                      ],
                             '.af' => [
                                        'NONE',
                                        '#',
                                        'was',
                                        'whois.nic.af'
                                      ],
                             '.no' => [
                                        'whois.norid.no'
                                      ],
                             '.to' => [
                                        'whois.tonic.to'
                                      ],
                             '-is' => [
                                        'whois.isnet.is'
                                      ],
                             '.as' => [
                                        'whois.nic.as'
                                      ],
                             '.se.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '-6bone' => [
                                           'whois.6bone.net'
                                         ],
                             '-ap' => [
                                        'whois.apnic.net'
                                      ],
                             '.sa' => [
                                        'WEB',
                                        'http://www.saudinic.net.sa/domain/whois.htm'
                                      ],
                             '.io' => [
                                        'WEB',
                                        'http://www.io.io/whois.html'
                                      ],
                             '-cknic' => [
                                           'whois.nic.ck'
                                         ],
                             '.eu.org' => [
                                            'whois.eu.org'
                                          ],
                             '.lc' => [
                                        'NONE',
                                        '#',
                                        'http://www.isisworld.lc/domains/'
                                      ],
                             '-au' => [
                                        'whois.aunic.net'
                                      ],
                             '.hu' => [
                                        'whois.nic.hu'
                                      ],
                             '.museum' => [
                                            'whois.museum'
                                          ],
                             '.cf' => [
                                        'WEB',
                                        'http://www.nic.cf/whois.php3'
                                      ],
                             '.is' => [
                                        'whois.isnet.is'
                                      ],
                             '.de' => [
                                        'whois.denic.de'
                                      ],
                             '.mh' => [
                                        'NONE',
                                        '#',
                                        'www.nic.net.mh'
                                      ],
                             '.li' => [
                                        'whois.nic.li'
                                      ],
                             '.com.uy' => [
                                            'WEB',
                                            'http://dns.antel.net.uy/clientes/consultar.htm'
                                          ],
                             '.gn' => [
                                        'NONE',
                                        '#',
                                        'http://www.psg.com/dns/gn/'
                                      ],
                             '.nf' => [
                                        'NONE',
                                        '#',
                                        'http://www.names.nf'
                                      ],
                             '.si' => [
                                        'whois.arnes.si'
                                      ],
                             '.uy.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.il' => [
                                        'whois.isoc.org.il'
                                      ],
                             '.dm' => [
                                        'NONE',
                                        '#',
                                        'www.domains.dm',
                                        '?'
                                      ],
                             '.br' => [
                                        'whois.nic.br'
                                      ],
                             '.cr' => [
                                        'WEB',
                                        'http://www.nic.cr/consulta-dns.html'
                                      ],
                             '-kg' => [
                                        'whois.domain.kg'
                                      ],
                             '-ti' => [
                                        'whois.telstra.net'
                                      ],
                             '.my' => [
                                        'NONE',
                                        '#',
                                        'http://www.mynic.net'
                                      ],
                             '.nl' => [
                                        'whois.domain-registry.nl'
                                      ],
                             '.gh' => [
                                        'NONE',
                                        '#',
                                        'http://www.ghana.com/domreg.html'
                                      ],
                             '-rotld' => [
                                           'whois.rotld.ro'
                                         ],
                             '.sa.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '.sb' => [
                                        'WEB',
                                        'http://www.sbnic.net.sb/search.html'
                                      ],
                             '.pl' => [
                                        'whois.dns.pl'
                                      ],
                             '.us.com' => [
                                            'whois.centralnic.net'
                                          ],
                             '-ripe' => [
                                          'whois.ripe.net'
                                        ],
                             '.am' => [
                                        'WEB',
                                        'https://www.amnic.net/whois/'
                                      ],
                             '.bi' => [
                                        'WEB',
                                        'http://www.nic.bi/cgi-bin/whoisbi.pl'
                                      ],
                             '.ag' => [
                                        'WEB',
                                        'http://www.nic.ag/domain_search.htm'
                                      ],
                             '.bf' => [
                                        'NONE',
                                        '#',
                                        'http://www.onatel.bf/domaine.htm'
                                      ],
                             '.net.za' => [
                                            'whois.net.za'
                                          ],
                             '.org.za' => [
                                            'WEB',
                                            'http://www.org.za/',
                                            '#',
                                            'rwhois.org.za:4321'
                                          ],
                             '.mt' => [
                                        'WEB',
                                        'http://www.um.edu.mt/nic/dir/'
                                      ],
                             '.gs' => [
                                        'whois.adamsnames.tc'
                                      ],
                             '.hm' => [
                                        'whois.registry.hm'
                                      ],
                             '.ph' => [
                                        'WEB',
                                        'http://www.names.ph/search.html'
                                      ],
                             '.uy' => [
                                        'WEB',
                                        'http://www.rau.edu.uy/rau/dom/reg.htm'
                                      ],
                             '.edu.cn' => [
                                            'whois.edu.cn'
                                          ],
                             '.ie' => [
                                        'whois.domainregistry.ie'
                                      ],
                             '.ac.uk' => [
                                           'whois.ja.net'
                                         ],
                             '.np' => [
                                        'WEB',
                                        'http://www.mos.com.np/domsearch.html'
                                      ],
                             '.se' => [
                                        'whois.nic-se.se'
                                      ],
                             '.lt' => [
                                        'whois.ripe.net'
                                      ],
                             '.re' => [
                                        'whois.nic.fr'
                                      ],
                             '.jo' => [
                                        'WEB',
                                        'http://amon.nic.gov.jo/dns/'
                                      ],
                             '.uk' => [
                                        'whois.nic.uk'
                                      ],
                             '-gandi' => [
                                           'whois.gandi.net'
                                         ],
                             '.pt' => [
                                        'NONE',
                                        '#',
                                        'www.dns.pt'
                                      ],
                             '-cz' => [
                                        'whois.nic.cz'
                                      ],
                             '.gf' => [
                                        'whois.nplus.gf'
                                      ],
                             '.ir' => [
                                        'WEB',
                                        'http://aria.nic.ir/forms/whois.html'
                                      ],
                             '.pe' => [
                                        'whois.rcp.net.pe'
                                      ],
                             '.sm' => [
                                        'whois.ripe.net'
                                      ]
                           );

sub new {
  my $self = bless { data => \%data }, shift;
  return $self;
}

sub dump_tlds {
  my $self = shift;
  print STDERR Dumper( $self->{data} );
  return 1;
}

sub tld {
  my $self = shift;
  my $lookup = shift || return;

  foreach my $tld ( keys %{ $self->{data} } ) {
	if ( $lookup =~ /\Q$tld\E$/ ) {
		return @{ $self->{data}->{ $tld } };
	}
  }
  return;
}

1;

__END__

=head1 NAME

POE::Component::Client::Whois::TLDList - determine the applicable Whois server for a given Top-level domain (TLD).

=head1 SYNOPSIS

  use strict;
  use POE::Component::Client::Whois::TLDList;

  my $tldlist = POE::Component::Client::Whois::TLDList->new();

  my $whois_server = $tldlist->tld('foobar.com');

  $tldlist->dump_tlds();

=head1 DESCRIPTION

E::Component::Client::Whois::TLDList contains a list of top-level domains mapped to which Whois server has information for that domain.


=head1 CONSTRUCTOR

=over

=item new

Returns a POE::Component::Client::Whois::TLDList object.

=back

=head1 METHODS

=over

=item tld

Takes a domain or hostname and returns a list or an undef on failure. The list returned usually has the
reponsible Whois server as the first item in the list, but some TLDs do not have Whois servers.

If the first item in the list is 'NONE' then that TLD doesn't have a Whois server or the Whois is unknown.

If the first item in the list is 'WEB' then that TLD has a web interface only to query whois. The second item will usually be the web url to query.

=item dump_tlds

Uses Data::Dumper to dump TLD data to STDERR.

=back

=head1 AUTHOR

Chris 'BinGOs' Williams

=head1 LICENSE

Copyright C<(c)> Chris Williams

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.
