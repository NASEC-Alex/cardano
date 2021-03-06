#!/bin/bash
##
## Create TX Raw to copy to cold environment
##

echo -e $'What is the current name of the era?'
read era


echo 'What is the destination address for this transaction?'
read dest

echo -e $'How much LOVELACE to send?'
read amountToSend
echo $'\n'

amountInAda=$(echo "scale=6; $amountToSend / 1000000" | bc -l)
echo -e $"Current era is: $era"
echo -e $"Sending to destination address: $dest"
echo -e $"Amount of Ada being sent: $amountInAda"
echo $'\n'

echo 'Please confirm the above are correct: [y/N]'
read verify

if  [ "$verify" == "y" ]
    then
        currentSlot=$(cardano-cli query tip --mainnet | jq -r '.slotNo')
        echo -e $"Current Slot: $currentSlot"
        echo $'\n'

        #Get total balance and UTXos
        cardano-cli query utxo \
            --address $(cat ~/cnode/keys/payment.addr) \
            --$(echo $era)-era \
            --mainnet > fullUtxo.out
        tail -n +3 fullUtxo.out | sort -k3 -nr > balance.out
        cat balance.out

        tx_in=""
        total_balance=0
        while read -r utxo; do
            in_addr=$(awk '{ print $1 }' <<< "${utxo}")
            idx=$(awk '{ print $2 }' <<< "${utxo}")
            utxo_balance=$(awk '{ print $3 }' <<< "${utxo}")
            total_balance=$((${total_balance}+${utxo_balance}))
            echo TxHash: ${in_addr}#${idx}
            echo ADA: ${utxo_balance}
            tx_in="${tx_in} --tx-in ${in_addr}#${idx}"
        done < balance.out
        txcnt=$(cat balance.out | wc -l)
        echo Total ADA balance: ${total_balance}
        echo Number of UTXOs: ${txcnt}

        #Build raw transaction
        cardano-cli transaction build-raw \
            ${tx_in} \
            --tx-out $(cat ~/cnode/keys/payment.addr)+0 \
            --tx-out $(echo $dest)+0 \
            --invalid-hereafter $(( ${currentSlot} + 10000)) \
            --fee 0 \
            --$(echo $era)-era \
            --out-file tx.tmp


        #Calculate minimum fee
        fee=$(cardano-cli transaction calculate-min-fee \
            --tx-body-file tx.tmp \
            --tx-in-count ${txcnt} \
            --tx-out-count 2 \
            --mainnet \
            --witness-count 1 \
            --byron-witness-count 0 \
            --protocol-params-file ~/cnode/keys/params.json | awk '{ print $1 }')
        echo fee: $fee
        #Calculate your change output
        txOut=$((${total_balance}-${fee}-${amountToSend}))
        echo Change Output: ${txOut}

        #Build Raw transaction
        cardano-cli transaction build-raw \
            ${tx_in} \
            --tx-out $(cat ~/cnode/keys/payment.addr)+${txOut} \
            --tx-out $(echo $dest)+${amountToSend} \
            --invalid-hereafter $(( ${currentSlot} + 10000)) \
            --fee ${fee} \
            --$(echo $era)-era \
            --out-file tx.raw

        echo $'\n'

        echo $'Now go and sign the transaction in your COLD environment\n'
        echo $'\n'
        echo $'cardano-cli transaction sign \
    --tx-body-file tx.raw \
    --signing-key-file payment.skey \
    --mainnet \
    --out-file tx.signed'

        echo $'\n'
        echo "Then submit the transaction from your HOT envirnoment"
        echo $'\n'


        echo $'cardano-cli transaction submit \
    --tx-file tx.signed \
    --mainnet'

        echo $'\n'
        echo "RAW Transaction successfully created!"

    else
        echo CANCELLING transaction
fi

exit
