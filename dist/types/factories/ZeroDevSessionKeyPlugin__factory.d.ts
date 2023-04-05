import { Signer, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../common";
import type { ZeroDevSessionKeyPlugin, ZeroDevSessionKeyPluginInterface } from "../ZeroDevSessionKeyPlugin";
type ZeroDevSessionKeyPluginConstructorParams = [signer?: Signer] | ConstructorParameters<typeof ContractFactory>;
export declare class ZeroDevSessionKeyPlugin__factory extends ContractFactory {
    constructor(...args: ZeroDevSessionKeyPluginConstructorParams);
    deploy(overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): Promise<ZeroDevSessionKeyPlugin>;
    getDeployTransaction(overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): TransactionRequest;
    attach(address: string): ZeroDevSessionKeyPlugin;
    connect(signer: Signer): ZeroDevSessionKeyPlugin__factory;
    static readonly bytecode = "0x6101406040523480156200001257600080fd5b506040518060400160405280601781526020017f5a65726f44657653657373696f6e4b6579506c7567696e0000000000000000008152506040518060400160405280600581526020017f302e302e3100000000000000000000000000000000000000000000000000000081525060008280519060200120905060008280519060200120905060007f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f90508260e081815250508161010081815250504660a08181525050620000e88184846200013760201b60201c565b608081815250503073ffffffffffffffffffffffffffffffffffffffff1660c08173ffffffffffffffffffffffffffffffffffffffff168152505080610120818152505050505050506200024b565b6000838383463060405160200162000154959493929190620001ee565b6040516020818303038152906040528051906020012090509392505050565b6000819050919050565b620001888162000173565b82525050565b6000819050919050565b620001a3816200018e565b82525050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000620001d682620001a9565b9050919050565b620001e881620001c9565b82525050565b600060a0820190506200020560008301886200017d565b6200021460208301876200017d565b6200022360408301866200017d565b62000232606083018562000198565b620002416080830184620001dd565b9695505050505050565b60805160a05160c05160e05161010051610120516123446200029b6000396000610f6c01526000610fae01526000610f8d01526000610ec201526000610f1801526000610f4101526123446000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80636d0ae0461461005c57806384f4fc6a1461008c578063970aa9ad146100a85780639e2045ce146100db578063fa01dc061461010b575b600080fd5b61007660048036038101906100719190611392565b61013b565b60405161008391906113d8565b60405180910390f35b6100a660048036038101906100a19190611392565b61018d565b005b6100c260048036038101906100bd9190611458565b610234565b6040516100d29493929190611503565b60405180910390f35b6100f560048036038101906100f091906115c5565b610447565b604051610102919061164f565b60405180910390f35b61012560048036038101906101209190611392565b61049c565b604051610132919061164f565b60405180910390f35b60006101456104fb565b60010160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60016101976104fb565b60000160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055508073ffffffffffffffffffffffffffffffffffffffff167f17c796fb82086b3c9effaec517342e5ca9ed8fd78c339137ec082f748ab60cbe60405160405180910390a250565b36600036600080868660009060209261024f93929190611674565b9061025a91906116c7565b60001c90506000878783906020856102729190611755565b9261027f93929190611674565b9061028a91906116c7565b60001c9050600088886020906040926102a593929190611674565b906102b091906116c7565b60001c90506000898983906020856102c89190611755565b926102d593929190611674565b906102e091906116c7565b60001c905089896020866102f49190611755565b90856020886103039190611755565b61030d9190611755565b9261031a93929190611674565b97509750898960208461032d9190611755565b908360208661033c9190611755565b6103469190611755565b9261035393929190611674565b95509550816020808561036691906117b8565b61037091906117e9565b60408661037d9190611755565b6103879190611755565b146103c7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103be90611888565b60405180910390fd5b89899050602080836103d991906117b8565b6103e391906117e9565b6040846103f09190611755565b6103fa9190611755565b1461043a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610431906118f4565b60405180910390fd5b5050505092959194509250565b6000366000366000610479888061014001906104639190611923565b606190809261047493929190611674565b610234565b935093509350935061048f88888686868661053a565b9450505050509392505050565b60006104a66104fb565b60000160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff169050919050565b60008060017f6da8a1d7d4f224b5b2581a964c1890eb7e987638c691727e5a2a14ca24d03fd960001c61052e9190611986565b60001b90508091505090565b600080858560009060149261055193929190611674565b9061055c91906119e6565b60601c90506105696104fb565b60000160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16156105f7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105ee90611a91565b60405180910390fd5b87602001356106046104fb565b60010160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414610685576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161067c90611afd565b60405180910390fd5b6106c36040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b600086866014906034926106d993929190611674565b906106e491906116c7565b90506107246040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b60008585600081811061073a57610739611b1d565b5b9050013560f81c60f81b60f81c90506107876040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b60606107c76040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b60006108076040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b60148360ff160361091f57878760019060159261082693929190611674565b604051610834929190611b7c565b604051809103902090508787605690809261085193929190611674565b81019061085e9190611cd3565b9150878760019060159261087493929190611674565b604051610882929190611b7c565b60405180910390208c806060019061089a9190611923565b6010906024926108ac93929190611674565b6040516108ba929190611b7c565b604051809103902014610902576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108f990611d68565b60405180910390fd5b878760159060569261091693929190611674565b97509750610b35565b60188360ff1603610af957878760019060199261093e93929190611674565b60405161094c929190611b7c565b604051809103902090508787605a90809261096993929190611674565b8101906109769190611cd3565b9150878760019060159261098c93929190611674565b60405161099a929190611b7c565b60405180910390208c80606001906109b29190611923565b6010906024926109c493929190611674565b6040516109d2929190611b7c565b604051809103902014610a1a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a1190611d68565b60405180910390fd5b60008c8060600190610a2c9190611923565b604490606492610a3e93929190611674565b90610a4991906116c7565b60001c90503660008e8060600190610a619190611923565b602085610a6e9190611755565b90602486610a7c9190611755565b92610a8993929190611674565b915091508a8a601590601992610aa193929190611674565b604051610aaf929190611b7c565b60405180910390208282604051610ac7929190611d88565b604051809103902014610ad957600080fd5b8a8a601990605a92610aed93929190611674565b9a509a50505050610b34565b6040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b2b90611ded565b60405180910390fd5b5b610b736040518060400160405280600281526020017f5a5a000000000000000000000000000000000000000000000000000000000000815250610d4e565b610b7e828583610de7565b610bbd576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610bb490611e59565b60405180910390fd5b6000610c6e7ff0a98eef9608fd8bfe5833dfbc8b73ab86d0355db37a1f539565c5985ad1c2428d610bec6104fb565b60010160008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000815480929190610c3d90611e79565b91905055604051602001610c5393929190611ed0565b60405160208183030381529060405280519060200120610dfe565b90506000610cc98a8a8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505083610e1890919063ffffffff16565b90508673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610d39576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d3090611f53565b60405180910390fd5b60019750505050505050509695505050505050565b610de481604051602401610d629190611fe1565b6040516020818303038152906040527f41304fac000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050610e3f565b50565b600082610df48584610e68565b1490509392505050565b6000610e11610e0b610ebe565b83610fd8565b9050919050565b6000806000610e27858561100b565b91509150610e348161105c565b819250505092915050565b60008151905060006a636f6e736f6c652e6c6f679050602083016000808483855afa5050505050565b60008082905060005b8451811015610eb357610e9e82868381518110610e9157610e90611b1d565b5b60200260200101516111c2565b91508080610eab90611e79565b915050610e71565b508091505092915050565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163073ffffffffffffffffffffffffffffffffffffffff16148015610f3a57507f000000000000000000000000000000000000000000000000000000000000000046145b15610f67577f00000000000000000000000000000000000000000000000000000000000000009050610fd5565b610fd27f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000006111ed565b90505b90565b60008282604051602001610fed92919061207b565b60405160208183030381529060405280519060200120905092915050565b600080604183510361104c5760008060006020860151925060408601519150606086015160001a905061104087828585611227565b94509450505050611055565b60006002915091505b9250929050565b600060048111156110705761106f6120b2565b5b816004811115611083576110826120b2565b5b03156111bf576001600481111561109d5761109c6120b2565b5b8160048111156110b0576110af6120b2565b5b036110f0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016110e79061212d565b60405180910390fd5b60026004811115611104576111036120b2565b5b816004811115611117576111166120b2565b5b03611157576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161114e90612199565b60405180910390fd5b6003600481111561116b5761116a6120b2565b5b81600481111561117e5761117d6120b2565b5b036111be576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016111b59061222b565b60405180910390fd5b5b50565b60008183106111da576111d58284611309565b6111e5565b6111e48383611309565b5b905092915050565b6000838383463060405160200161120895949392919061225a565b6040516020818303038152906040528051906020012090509392505050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08360001c1115611262576000600391509150611300565b60006001878787876040516000815260200160405260405161128794939291906122c9565b6020604051602081039080840390855afa1580156112a9573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036112f757600060019250925050611300565b80600092509250505b94509492505050565b600082600052816020526040600020905092915050565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061135f82611334565b9050919050565b61136f81611354565b811461137a57600080fd5b50565b60008135905061138c81611366565b92915050565b6000602082840312156113a8576113a761132a565b5b60006113b68482850161137d565b91505092915050565b6000819050919050565b6113d2816113bf565b82525050565b60006020820190506113ed60008301846113c9565b92915050565b600080fd5b600080fd5b600080fd5b60008083601f840112611418576114176113f3565b5b8235905067ffffffffffffffff811115611435576114346113f8565b5b602083019150836001820283011115611451576114506113fd565b5b9250929050565b6000806020838503121561146f5761146e61132a565b5b600083013567ffffffffffffffff81111561148d5761148c61132f565b5b61149985828601611402565b92509250509250929050565b600082825260208201905092915050565b82818337600083830152505050565b6000601f19601f8301169050919050565b60006114e283856114a5565b93506114ef8385846114b6565b6114f8836114c5565b840190509392505050565b6000604082019050818103600083015261151e8186886114d6565b905081810360208301526115338184866114d6565b905095945050505050565b600080fd5b6000610160828403121561155a5761155961153e565b5b81905092915050565b6000819050919050565b61157681611563565b811461158157600080fd5b50565b6000813590506115938161156d565b92915050565b6115a2816113bf565b81146115ad57600080fd5b50565b6000813590506115bf81611599565b92915050565b6000806000606084860312156115de576115dd61132a565b5b600084013567ffffffffffffffff8111156115fc576115fb61132f565b5b61160886828701611543565b935050602061161986828701611584565b925050604061162a868287016115b0565b9150509250925092565b60008115159050919050565b61164981611634565b82525050565b60006020820190506116646000830184611640565b92915050565b600080fd5b600080fd5b600080858511156116885761168761166a565b5b838611156116995761169861166f565b5b6001850283019150848603905094509492505050565b600082905092915050565b600082821b905092915050565b60006116d383836116af565b826116de8135611563565b9250602082101561171e576117197fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff836020036008026116ba565b831692505b505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000611760826113bf565b915061176b836113bf565b925082820190508082111561178357611782611726565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006117c3826113bf565b91506117ce836113bf565b9250826117de576117dd611789565b5b828204905092915050565b60006117f4826113bf565b91506117ff836113bf565b925082820261180d816113bf565b9150828204841483151761182457611823611726565b5b5092915050565b600082825260208201905092915050565b7f696e76616c696420646174610000000000000000000000000000000000000000600082015250565b6000611872600c8361182b565b915061187d8261183c565b602082019050919050565b600060208201905081810360008301526118a181611865565b9050919050565b7f696e76616c6964207369676e6174757265000000000000000000000000000000600082015250565b60006118de60118361182b565b91506118e9826118a8565b602082019050919050565b6000602082019050818103600083015261190d816118d1565b9050919050565b600080fd5b600080fd5b600080fd5b600080833560016020038436030381126119405761193f611914565b5b80840192508235915067ffffffffffffffff82111561196257611961611919565b5b60208301925060018202360383131561197e5761197d61191e565b5b509250929050565b6000611991826113bf565b915061199c836113bf565b92508282039050818111156119b4576119b3611726565b5b92915050565b60007fffffffffffffffffffffffffffffffffffffffff00000000000000000000000082169050919050565b60006119f283836116af565b826119fd81356119ba565b92506014821015611a3d57611a387fffffffffffffffffffffffffffffffffffffffff000000000000000000000000836014036008026116ba565b831692505b505092915050565b7f73657373696f6e206b6579207265766f6b656400000000000000000000000000600082015250565b6000611a7b60138361182b565b9150611a8682611a45565b602082019050919050565b60006020820190508181036000830152611aaa81611a6e565b9050919050565b7f6e6f6e6365206d69736d61746368000000000000000000000000000000000000600082015250565b6000611ae7600e8361182b565b9150611af282611ab1565b602082019050919050565b60006020820190508181036000830152611b1681611ada565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600081905092915050565b6000611b638385611b4c565b9350611b708385846114b6565b82840190509392505050565b6000611b89828486611b57565b91508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611bcd826114c5565b810181811067ffffffffffffffff82111715611bec57611beb611b95565b5b80604052505050565b6000611bff611320565b9050611c0b8282611bc4565b919050565b600067ffffffffffffffff821115611c2b57611c2a611b95565b5b602082029050602081019050919050565b6000611c4f611c4a84611c10565b611bf5565b90508083825260208201905060208402830185811115611c7257611c716113fd565b5b835b81811015611c9b5780611c878882611584565b845260208401935050602081019050611c74565b5050509392505050565b600082601f830112611cba57611cb96113f3565b5b8135611cca848260208601611c3c565b91505092915050565b600060208284031215611ce957611ce861132a565b5b600082013567ffffffffffffffff811115611d0757611d0661132f565b5b611d1384828501611ca5565b91505092915050565b7f696e76616c69642073657373696f6e206b657900000000000000000000000000600082015250565b6000611d5260138361182b565b9150611d5d82611d1c565b602082019050919050565b60006020820190508181036000830152611d8181611d45565b9050919050565b6000611d95828486611b57565b91508190509392505050565b7f696e76616c6964206c656166206c656e67746800000000000000000000000000600082015250565b6000611dd760138361182b565b9150611de282611da1565b602082019050919050565b60006020820190508181036000830152611e0681611dca565b9050919050565b7f696e76616c696465206d65726b6c6520726f6f74000000000000000000000000600082015250565b6000611e4360148361182b565b9150611e4e82611e0d565b602082019050919050565b60006020820190508181036000830152611e7281611e36565b9050919050565b6000611e84826113bf565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611eb657611eb5611726565b5b600182019050919050565b611eca81611563565b82525050565b6000606082019050611ee56000830186611ec1565b611ef26020830185611ec1565b611eff60408301846113c9565b949350505050565b7f6163636f756e743a20696e76616c6964207369676e6174757265000000000000600082015250565b6000611f3d601a8361182b565b9150611f4882611f07565b602082019050919050565b60006020820190508181036000830152611f6c81611f30565b9050919050565b600081519050919050565b60005b83811015611f9c578082015181840152602081019050611f81565b60008484015250505050565b6000611fb382611f73565b611fbd818561182b565b9350611fcd818560208601611f7e565b611fd6816114c5565b840191505092915050565b60006020820190508181036000830152611ffb8184611fa8565b905092915050565b600081905092915050565b7f1901000000000000000000000000000000000000000000000000000000000000600082015250565b6000612044600283612003565b915061204f8261200e565b600282019050919050565b6000819050919050565b61207561207082611563565b61205a565b82525050565b600061208682612037565b91506120928285612064565b6020820191506120a28284612064565b6020820191508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b7f45434453413a20696e76616c6964207369676e61747572650000000000000000600082015250565b600061211760188361182b565b9150612122826120e1565b602082019050919050565b600060208201905081810360008301526121468161210a565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265206c656e67746800600082015250565b6000612183601f8361182b565b915061218e8261214d565b602082019050919050565b600060208201905081810360008301526121b281612176565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265202773272076616c60008201527f7565000000000000000000000000000000000000000000000000000000000000602082015250565b600061221560228361182b565b9150612220826121b9565b604082019050919050565b6000602082019050818103600083015261224481612208565b9050919050565b61225481611354565b82525050565b600060a08201905061226f6000830188611ec1565b61227c6020830187611ec1565b6122896040830186611ec1565b61229660608301856113c9565b6122a3608083018461224b565b9695505050505050565b600060ff82169050919050565b6122c3816122ad565b82525050565b60006080820190506122de6000830187611ec1565b6122eb60208301866122ba565b6122f86040830185611ec1565b6123056060830184611ec1565b9594505050505056fea2646970667358221220595afa68fbe75aa67e4f5b164b962e6c66fa1a5ab222aec98049f438caf637a164736f6c63430008120033";
    static readonly abi: readonly [{
        readonly inputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "constructor";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "key";
            readonly type: "address";
        }];
        readonly name: "SessionKeyRevoked";
        readonly type: "event";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes";
            readonly name: "_packed";
            readonly type: "bytes";
        }];
        readonly name: "parseDataAndSignature";
        readonly outputs: readonly [{
            readonly internalType: "bytes";
            readonly name: "data";
            readonly type: "bytes";
        }, {
            readonly internalType: "bytes";
            readonly name: "signature";
            readonly type: "bytes";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "revokeSessionKey";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "revoked";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "sessionNonce";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "address";
                readonly name: "sender";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "nonce";
                readonly type: "uint256";
            }, {
                readonly internalType: "bytes";
                readonly name: "initCode";
                readonly type: "bytes";
            }, {
                readonly internalType: "bytes";
                readonly name: "callData";
                readonly type: "bytes";
            }, {
                readonly internalType: "uint256";
                readonly name: "callGasLimit";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "verificationGasLimit";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "preVerificationGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "maxFeePerGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "maxPriorityFeePerGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "bytes";
                readonly name: "paymasterAndData";
                readonly type: "bytes";
            }, {
                readonly internalType: "bytes";
                readonly name: "signature";
                readonly type: "bytes";
            }];
            readonly internalType: "struct UserOperation";
            readonly name: "userOp";
            readonly type: "tuple";
        }, {
            readonly internalType: "bytes32";
            readonly name: "userOpHash";
            readonly type: "bytes32";
        }, {
            readonly internalType: "uint256";
            readonly name: "missingAccountFunds";
            readonly type: "uint256";
        }];
        readonly name: "validatePluginData";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "validated";
            readonly type: "bool";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }];
    static createInterface(): ZeroDevSessionKeyPluginInterface;
    static connect(address: string, signerOrProvider: Signer | Provider): ZeroDevSessionKeyPlugin;
}
export {};
